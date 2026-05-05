"""Tests for hard-coded user input shortcut preprocessing."""

from cli import _preprocess_user_message_shortcuts


class TestSinglePeriodContinueShortcut:
    def test_single_period_becomes_continue(self):
        assert _preprocess_user_message_shortcuts(".") == "继续上一任务。"

    def test_surrounding_whitespace_still_counts_as_single_period(self):
        assert _preprocess_user_message_shortcuts("  .  ") == "继续上一任务。"
        assert _preprocess_user_message_shortcuts("\n.\n") == "继续上一任务。"

    def test_period_with_other_text_does_not_trigger(self):
        samples = [
            ".继续",
            ". 继续",
            ".abc",
            "..",
            "...",
            " . abc",
            "hello.",
            "我觉得。",
        ]
        for sample in samples:
            assert _preprocess_user_message_shortcuts(sample) == sample

    def test_non_ascii_full_stop_does_not_trigger(self):
        assert _preprocess_user_message_shortcuts("。") == "。"
        assert _preprocess_user_message_shortcuts("．") == "．"

    def test_non_string_passthrough(self):
        value = {"type": "text", "text": "."}
        assert _preprocess_user_message_shortcuts(value) is value
