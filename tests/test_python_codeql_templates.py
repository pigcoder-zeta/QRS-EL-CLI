import subprocess

import pytest

from src.utils.ql_template_library import QLTemplateLibrary


def test_python_sql_template_compiles_with_local_codeql(tmp_path):
    template = QLTemplateLibrary.find("python", "SQL Injection")
    assert template is not None

    query_dir = tmp_path / "queries"
    query_dir.mkdir()
    (query_dir / "qlpack.yml").write_text(
        'name: argus-test/python-queries\n'
        'version: 0.0.1\n'
        'dependencies:\n'
        '  "codeql/python-all": "*"\n',
        encoding="utf-8",
    )
    query_path = query_dir / "python_sql_injection.ql"
    query_path.write_text(template.code, encoding="utf-8")

    try:
        result = subprocess.run(
            ["codeql", "query", "compile", str(query_path)],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
    except FileNotFoundError:
        pytest.skip("CodeQL CLI is not installed")

    assert result.returncode == 0, result.stderr or result.stdout
