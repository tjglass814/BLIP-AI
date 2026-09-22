import pytest

from blip_core.tools.guardrails import (
    GuardrailViolation,
    check_max_range,
    check_no_embedded_time_modifiers,
    check_read_only_spl,
)


class TestReadOnlySpl:
    def test_plain_search_passes(self):
        check_read_only_spl('search index=main sourcetype=linux_secure "Failed password"')

    def test_implicit_search_with_no_leading_keyword_passes(self):
        check_read_only_spl('index=main sourcetype=linux_secure "Failed password"')

    def test_stats_and_eval_pass(self):
        check_read_only_spl('search index=main | stats count by src_ip | eval risk="HIGH"')

    def test_chained_allowed_commands_pass(self):
        check_read_only_spl(
            "search index=main | bin span=1h _time | stats count by _time | sort -count | head 10"
        )

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

    def test_unrecognized_command_not_in_allowlist_is_rejected(self):
        """
        The allowlist must fail closed on a command it doesn't recognize
        at all, not just the specific write commands the old denylist
        happened to enumerate.
        """
        with pytest.raises(GuardrailViolation):
            check_read_only_spl("search index=main | somebrandnewcommand foo=bar")

    def test_unrecognized_leading_command_is_rejected(self):
        with pytest.raises(GuardrailViolation):
            check_read_only_spl("somebrandnewcommand index=main")


class TestNoEmbeddedTimeModifiers:
    def test_query_without_time_modifier_passes(self):
        check_no_embedded_time_modifiers("search index=main sourcetype=linux_secure")

    def test_embedded_earliest_modifier_is_rejected(self):
        with pytest.raises(GuardrailViolation):
            check_no_embedded_time_modifiers("search index=main earliest=-90d")

    def test_embedded_latest_modifier_is_rejected(self):
        with pytest.raises(GuardrailViolation):
            check_no_embedded_time_modifiers("search index=main latest=now-1s")

    def test_embedded_modifier_after_a_pipe_is_still_rejected(self):
        with pytest.raises(GuardrailViolation):
            check_no_embedded_time_modifiers("search index=main | eval x=1 earliest=-1y")

    def test_field_name_containing_earliest_as_substring_is_not_falsely_flagged(self):
        check_no_embedded_time_modifiers("search index=main index_earliest=foo")


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
