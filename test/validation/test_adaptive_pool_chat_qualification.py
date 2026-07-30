import importlib.util
from pathlib import Path
import sys
import unittest


MODULE_PATH = Path(__file__).with_name("adaptive_pool_chat_qualification.py")
SPEC = importlib.util.spec_from_file_location("adaptive_pool_chat_qualification", MODULE_PATH)
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


class ChatQualificationClassifierTest(unittest.TestCase):
    def test_chatgpt_region_block(self):
        result = MODULE.classify_chat_page(
            "chatgpt", "https://chatgpt.com/", "ChatGPT", "Unsupported country", "complete"
        )
        self.assertEqual("blocked_region", result["outcome"])
        self.assertEqual("region_marker", result["signal"])

    def test_claude_region_block(self):
        result = MODULE.classify_chat_page(
            "claude", "https://claude.ai/", "Claude", "Claude is not available in your region", "complete"
        )
        self.assertEqual("blocked_region", result["outcome"])

    def test_claude_official_redirect_is_eligible(self):
        result = MODULE.classify_chat_page(
            "claude", "https://claude.com/", "Claude", "Meet Claude, your AI assistant", "complete"
        )
        self.assertEqual("eligible", result["outcome"])

    def test_gemini_login_redirect_is_eligible(self):
        result = MODULE.classify_chat_page(
            "gemini", "https://accounts.google.com/v3/signin", "Sign in", "Use your Google Account", "complete"
        )
        self.assertEqual("eligible", result["outcome"])

    def test_cloudflare_challenge_is_transient(self):
        result = MODULE.classify_chat_page(
            "chatgpt", "https://chatgpt.com/", "Just a moment", "Verify you are human", "complete"
        )
        self.assertEqual("transient_challenge", result["outcome"])

    def test_unexpected_redirect_is_invalid(self):
        result = MODULE.classify_chat_page(
            "chatgpt", "https://example.invalid/", "Example", "Hello world from another site", "complete"
        )
        self.assertEqual("invalid", result["outcome"])

    def test_output_does_not_include_page_body(self):
        secret = "secret-cookie-token"
        result = MODULE.classify_chat_page(
            "chatgpt", "https://chatgpt.com/", "ChatGPT", f"Welcome {secret} to ChatGPT", "complete"
        )
        self.assertEqual("eligible", result["outcome"])
        self.assertNotIn(secret, repr(result))


if __name__ == "__main__":
    unittest.main()
