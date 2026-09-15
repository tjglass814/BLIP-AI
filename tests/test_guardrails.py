import pytest

from blip_core.tools.guardrails import GuardrailViolation, check_max_range, check_read_only_spl


class TestReadOnlySpl:
    def test_plain_search_passes(self):
        check_read_only_spl('search index=main sourcetype=linux_secure "Failed password"')

    def test_stats_and_eval_pass(self):
        check_read_only_spl('search index=main | stats count by src_ip | eval risk="HIGH"')

    @pytest.mark.parametrize(
        "spl",
        [
            "search index=main | delete",
            "search index=main | outputlookup blocklist.csv",
            "search index=main | outputcsv results.csv",
            "search index=main | collect index=summary",
            "search index=main | sendemail to=admin@example.com",
            "search index=main | script python evil.py",
            "search index=main | run some_command",
            'search index=main | map search="search index=main"',
            "search index=main | savedsearch some_saved_search",
        ],
    )
    def test_disallowed_commands_are_rejected(self, spl):
        with pytest.raises(GuardrailViolation):
            check_read_only_spl(spl)


class TestMaxRange:
    def test_within_limit_passes(self):
        check_max_range("-4h", "now")
        check_max_range("-24h", "now")

    def test_exceeding_limit_is_rejected(self):
        with pytest.raises(GuardrailViolation):
            check_max_range("-48h", "now")

    def test_days_are_converted_to_hours(self):
        with pytest.raises(GuardrailViolation):
            check_max_range("-2d", "now")

    def test_non_relative_time_is_rejected(self):
        with pytest.raises(GuardrailViolation):
            check_max_range("2026-01-01T00:00:00", "now")

    def test_non_now_latest_is_rejected(self):
        with pytest.raises(GuardrailViolation):
            check_max_range("-1h", "-30m")

    def test_custom_max_hours_is_respected(self):
        with pytest.raises(GuardrailViolation):
            check_max_range("-2h", "now", max_hours=1)
