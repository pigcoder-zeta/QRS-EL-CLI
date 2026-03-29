"""测试 QLTemplateLibrary：模板命中与未命中逻辑。"""

import pytest
from src.utils.ql_template_library import QLTemplateLibrary, _ALL_TEMPLATES


class TestQLTemplateLibrary:

    def test_find_spel_by_exact_keyword(self):
        tmpl = QLTemplateLibrary.find("java", "Spring EL Injection")
        assert tmpl is not None
        assert tmpl.language == "java"
        assert "spel" in tmpl.vuln_type or "spring" in tmpl.key

    def test_find_ognl(self):
        tmpl = QLTemplateLibrary.find("java", "OGNL Injection")
        assert tmpl is not None
        assert "ognl" in tmpl.key

    def test_find_mvel(self):
        tmpl = QLTemplateLibrary.find("java", "MVEL Injection")
        assert tmpl is not None
        assert "mvel" in tmpl.key

    def test_find_jinja2(self):
        tmpl = QLTemplateLibrary.find("python", "Jinja2 SSTI")
        assert tmpl is not None
        assert tmpl.language == "python"
        assert "jinja2" in tmpl.key

    def test_find_mako(self):
        tmpl = QLTemplateLibrary.find("python", "Mako Template Injection")
        assert tmpl is not None
        assert tmpl.language == "python"

    def test_find_ssti_generic(self):
        tmpl = QLTemplateLibrary.find("python", "SSTI vulnerability")
        assert tmpl is not None
        assert tmpl.language == "python"

    def test_no_match_returns_none(self):
        tmpl = QLTemplateLibrary.find("java", "SQL Injection totally unrelated")
        assert tmpl is None

    def test_language_mismatch(self):
        """Python 关键词不应匹配 Java 模板。"""
        tmpl = QLTemplateLibrary.find("java", "Jinja2 SSTI")
        assert tmpl is None

    def test_list_templates_returns_all_keys(self):
        keys = QLTemplateLibrary.list_templates()
        assert len(keys) == len(_ALL_TEMPLATES)
        assert "java/spring-el-injection" in keys
        assert "python/jinja2-ssti" in keys

    @pytest.mark.parametrize("tmpl", _ALL_TEMPLATES)
    def test_template_code_not_empty(self, tmpl):
        assert len(tmpl.code) > 100, f"模板 {tmpl.key} 的代码过短"

    @pytest.mark.parametrize("tmpl", _ALL_TEMPLATES)
    def test_template_has_required_fields(self, tmpl):
        assert tmpl.key
        assert tmpl.language in ("java", "python", "javascript", "go", "csharp")
        assert tmpl.vuln_type
        assert tmpl.description
