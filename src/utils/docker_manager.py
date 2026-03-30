"""
DockerManager：Docker 容器生命周期管理，为 Agent-E 动态沙箱验证提供底层支撑。

能力：
  - 检测 Docker 是否可用
  - 从项目仓库探测 Dockerfile / docker-compose.yml
  - 构建镜像（带超时 + 进度日志）
  - 启动容器并等待 HTTP 健康检查就绪
  - 执行 PoC HTTP 请求（requests 库）
  - 停止并删除容器
"""

from __future__ import annotations

import logging
import re
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# 超时常量
# ---------------------------------------------------------------------------

_TIMEOUT_BUILD   = 600   # 镜像构建最长 10 分钟
_TIMEOUT_START   = 120   # 容器启动 + 健康检查最长 2 分钟
_TIMEOUT_REQUEST = 15    # 单次 HTTP 请求超时（秒）

# ---------------------------------------------------------------------------
# 数据结构
# ---------------------------------------------------------------------------


@dataclass
class ContainerInfo:
    """运行中容器的基本信息。"""

    container_id: str
    image_tag: str
    host_port: int          # 映射到宿主机的端口
    base_url: str           # http://127.0.0.1:{host_port}
    started_at: float = field(default_factory=time.time)

    @property
    def alive_seconds(self) -> float:
        return time.time() - self.started_at


@dataclass
class DockerfileInfo:
    """仓库中探测到的容器化配置文件。"""

    dockerfile: Optional[Path] = None
    compose_file: Optional[Path] = None
    expose_port: int = 8080     # 默认暴露端口（从 EXPOSE 指令解析）
    start_cmd: str = ""         # docker-compose up / docker run 命令摘要

    @property
    def has_dockerfile(self) -> bool:
        return self.dockerfile is not None

    @property
    def has_compose(self) -> bool:
        return self.compose_file is not None

    @property
    def is_containerizable(self) -> bool:
        return self.has_dockerfile or self.has_compose


# ---------------------------------------------------------------------------
# DockerManager
# ---------------------------------------------------------------------------


class DockerManager:
    """
    Docker 容器生命周期管理器。

    设计为无状态，每次调用独立管理一个容器，
    调用方负责在 finally 块中调用 stop_container()。
    """

    # ------------------------------------------------------------------
    # 环境探测
    # ------------------------------------------------------------------

    @staticmethod
    def is_available() -> bool:
        """检查 Docker CLI 是否可用且 Daemon 正常运行。"""
        try:
            result = subprocess.run(
                ["docker", "info"],
                capture_output=True, text=True, timeout=10,
            )
            return result.returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    @staticmethod
    def probe_repo(repo_path: str) -> DockerfileInfo:
        """
        探测仓库中的 Dockerfile 和 docker-compose 文件。

        扫描顺序（优先级从高到低）：
          1. docker-compose.yml / docker-compose.yaml（最完整，通常包含环境变量和端口）
          2. Dockerfile（根目录优先，子目录次之）

        Args:
            repo_path: 仓库本地路径。

        Returns:
            DockerfileInfo，含文件路径 + 推断的暴露端口。
        """
        root = Path(repo_path)
        info = DockerfileInfo()

        # 探测 docker-compose
        for compose_name in ["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]:
            candidates = list(root.rglob(compose_name))
            if candidates:
                # 优先选择层级最浅的
                info.compose_file = min(candidates, key=lambda p: len(p.parts))
                info.expose_port = DockerManager._parse_compose_port(info.compose_file)
                logger.info("[DockerManager] 探测到 docker-compose: %s (端口: %d)", info.compose_file, info.expose_port)
                break

        # 探测 Dockerfile
        for dockerfile_name in ["Dockerfile", "dockerfile", "Dockerfile.prod", "Dockerfile.app"]:
            candidates = list(root.rglob(dockerfile_name))
            if candidates:
                info.dockerfile = min(candidates, key=lambda p: len(p.parts))
                if not info.compose_file:
                    port = DockerManager._parse_dockerfile_expose(info.dockerfile)
                    if port:
                        info.expose_port = port
                logger.info("[DockerManager] 探测到 Dockerfile: %s (EXPOSE: %d)", info.dockerfile, info.expose_port)
                break

        return info

    @staticmethod
    def _parse_dockerfile_expose(dockerfile: Path) -> int:
        """从 Dockerfile 解析 EXPOSE 指令中的端口号。"""
        try:
            content = dockerfile.read_text(encoding="utf-8", errors="replace")
            # 匹配第一个 EXPOSE 端口
            m = re.search(r"^\s*EXPOSE\s+(\d+)", content, re.MULTILINE | re.IGNORECASE)
            if m:
                return int(m.group(1))
        except Exception:
            pass
        return 8080

    @staticmethod
    def _parse_compose_port(compose_file: Path) -> int:
        """从 docker-compose.yml 解析服务映射端口。"""
        try:
            content = compose_file.read_text(encoding="utf-8", errors="replace")
            # 匹配 "- '8080:8080'" 或 "- 8080:8080" 格式
            m = re.search(r"['\"]?(\d+):(\d+)['\"]?", content)
            if m:
                return int(m.group(2))   # 容器内部端口
        except Exception:
            pass
        return 8080

    # ------------------------------------------------------------------
    # 镜像构建
    # ------------------------------------------------------------------

    def build_image(self, dockerfile_info: DockerfileInfo, image_tag: str) -> bool:
        """
        构建 Docker 镜像。

        Args:
            dockerfile_info: probe_repo() 返回的探测结果。
            image_tag:       镜像标签（如 qrs-el-target:latest）。

        Returns:
            True 表示构建成功。
        """
        if not dockerfile_info.has_dockerfile:
            logger.warning("[DockerManager] 无 Dockerfile，跳过构建。")
            return False

        build_dir = str(dockerfile_info.dockerfile.parent)
        dockerfile_path = str(dockerfile_info.dockerfile)
        cmd = ["docker", "build", "-t", image_tag, "-f", dockerfile_path, build_dir]

        logger.info("[DockerManager] 开始构建镜像: %s (Dockerfile: %s)", image_tag, dockerfile_path)
        try:
            result = subprocess.run(
                cmd,
                capture_output=True, text=True,
                timeout=_TIMEOUT_BUILD,
            )
            if result.returncode == 0:
                logger.info("[DockerManager] 镜像构建成功: %s", image_tag)
                return True
            else:
                logger.warning(
                    "[DockerManager] 镜像构建失败 (exit=%d):\n%s",
                    result.returncode, result.stderr[-1000:],
                )
                return False
        except subprocess.TimeoutExpired:
            logger.warning("[DockerManager] 镜像构建超时（%ds）。", _TIMEOUT_BUILD)
            return False

    # ------------------------------------------------------------------
    # 容器启动
    # ------------------------------------------------------------------

    def start_container(
        self,
        image_tag: str,
        container_port: int,
        host_port: Optional[int] = None,
        env_vars: Optional[dict[str, str]] = None,
    ) -> Optional[ContainerInfo]:
        """
        启动容器并等待 HTTP 健康检查就绪。

        Args:
            image_tag:      Docker 镜像标签。
            container_port: 容器内暴露的端口。
            host_port:      宿主机映射端口（None 则随机选择）。
            env_vars:       传入容器的环境变量。

        Returns:
            ContainerInfo（成功），None（失败）。
        """
        effective_port = host_port or self._find_free_port()
        cmd = [
            "docker", "run", "-d",
            "-p", f"{effective_port}:{container_port}",
            "--rm",   # 停止后自动删除
        ]
        for k, v in (env_vars or {}).items():
            cmd += ["-e", f"{k}={v}"]
        cmd.append(image_tag)

        logger.info(
            "[DockerManager] 启动容器 %s 端口映射 %d→%d",
            image_tag, effective_port, container_port,
        )
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                logger.warning("[DockerManager] 容器启动失败: %s", result.stderr[:500])
                return None

            container_id = result.stdout.strip()[:12]
            base_url = f"http://127.0.0.1:{effective_port}"
            info = ContainerInfo(
                container_id=container_id,
                image_tag=image_tag,
                host_port=effective_port,
                base_url=base_url,
            )
            logger.info("[DockerManager] 容器已启动: %s  URL: %s", container_id, base_url)

            # 等待 HTTP 健康检查就绪
            if self._wait_for_ready(base_url, timeout=_TIMEOUT_START):
                logger.info("[DockerManager] 应用已就绪: %s", base_url)
                return info
            else:
                logger.warning("[DockerManager] 应用未在 %ds 内就绪，尝试继续...", _TIMEOUT_START)
                return info   # 仍然返回，让 Agent-E 尝试发送请求

        except subprocess.TimeoutExpired:
            logger.warning("[DockerManager] 容器启动命令超时。")
            return None

    def _wait_for_ready(self, base_url: str, timeout: int = 60) -> bool:
        """轮询 GET / 直到返回非连接错误的响应。"""
        try:
            import requests as _req  # type: ignore
        except ImportError:
            time.sleep(5)
            return True

        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                resp = _req.get(base_url, timeout=3, allow_redirects=True)
                if resp.status_code < 600:
                    return True
            except Exception:
                pass
            time.sleep(2)
        return False

    # ------------------------------------------------------------------
    # HTTP 请求执行
    # ------------------------------------------------------------------

    def execute_request(
        self,
        base_url: str,
        method: str,
        path: str,
        params: Optional[dict] = None,
        data: Optional[dict] = None,
        headers: Optional[dict] = None,
        timeout: int = _TIMEOUT_REQUEST,
    ) -> tuple[int, str]:
        """
        向目标容器发送 HTTP 请求。

        Returns:
            (status_code, response_body_text)
        """
        try:
            import requests as _req  # type: ignore
        except ImportError:
            raise RuntimeError("requests 库未安装：pip install requests")

        url = base_url.rstrip("/") + "/" + path.lstrip("/")
        effective_headers = {"Content-Type": "application/x-www-form-urlencoded"}
        effective_headers.update(headers or {})

        logger.debug("[DockerManager] %s %s  params=%s  data=%s", method, url, params, data)

        try:
            resp = _req.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                headers=effective_headers,
                timeout=timeout,
                allow_redirects=True,
                verify=False,   # 自签名证书
            )
            return resp.status_code, resp.text
        except Exception as exc:
            logger.debug("[DockerManager] HTTP 请求异常: %s", exc)
            return -1, str(exc)

    # ------------------------------------------------------------------
    # 容器停止
    # ------------------------------------------------------------------

    def stop_container(self, container_id: str) -> None:
        """强制停止并删除容器（容器以 --rm 启动时自动删除）。"""
        try:
            subprocess.run(
                ["docker", "stop", container_id],
                capture_output=True, timeout=30,
            )
            logger.info("[DockerManager] 容器已停止: %s", container_id)
        except Exception as exc:
            logger.debug("[DockerManager] 停止容器时出错（可忽略）: %s", exc)

    def get_container_logs(self, container_id: str, tail: int = 50) -> str:
        """获取容器最新日志，用于调试。"""
        try:
            result = subprocess.run(
                ["docker", "logs", "--tail", str(tail), container_id],
                capture_output=True, text=True, timeout=10,
            )
            return result.stdout + result.stderr
        except Exception:
            return ""

    def remove_image(self, image_tag: str) -> None:
        """删除本地镜像（扫描结束后调用）。"""
        try:
            subprocess.run(
                ["docker", "rmi", "-f", image_tag],
                capture_output=True, timeout=30,
            )
            logger.info("[DockerManager] 镜像已删除: %s", image_tag)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 辅助
    # ------------------------------------------------------------------

    @staticmethod
    def _find_free_port(start: int = 18000, end: int = 19000) -> int:
        """在指定范围内找一个空闲端口。"""
        import random
        import socket
        for _ in range(50):
            port = random.randint(start, end)
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                if s.connect_ex(("127.0.0.1", port)) != 0:
                    return port
        return start
