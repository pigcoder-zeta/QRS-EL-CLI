from pathlib import Path
from types import SimpleNamespace


def test_cli_without_vuln_type_enters_auto_planner(monkeypatch, tmp_path):
    from src import main as cli

    captured = {}

    class DummyPipelineConfig:
        def __init__(self, **kwargs):
            self.__dict__.update(kwargs)

    class DummyCoordinator:
        @staticmethod
        def run_with_planner(base_config):
            captured["base_config"] = base_config
            return {
                "all_states": [],
                "rounds_completed": 0,
                "total_vulnerabilities": 0,
                "total_confirmed_pocs": 0,
            }

    class DummyHistory:
        def __init__(self, *args, **kwargs):
            pass

        def record(self, *args, **kwargs):
            captured["history_recorded"] = True

    monkeypatch.setenv("OPENAI_API_KEY", "sk-test")
    monkeypatch.setattr(
        "sys.argv",
        ["argus", "--source-dir", str(tmp_path)],
    )
    monkeypatch.setattr(
        "src.orchestrator.coordinator.PipelineConfig",
        DummyPipelineConfig,
    )
    monkeypatch.setattr(
        "src.orchestrator.coordinator.Coordinator",
        DummyCoordinator,
    )
    monkeypatch.setattr("src.main._print_rich_summary", lambda states: None)
    monkeypatch.setattr("src.utils.scan_history.ScanHistory", DummyHistory)

    try:
        cli.main()
    except SystemExit as exc:
        assert exc.code == 0

    assert captured["base_config"].vuln_type == "_auto_"
    assert captured["base_config"].language == ""
    assert Path(captured["base_config"].source_dir) == tmp_path.resolve()
