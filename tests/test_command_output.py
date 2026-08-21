import unittest

from xhttp_setup.command_output import english_words, parse_ufw_status


class CommandOutputTests(unittest.TestCase):
    def test_english_words_ignore_only_presentation_differences(self):
        self.assertEqual(
            english_words("  Added user rules (see 'UFW status')!  "),
            ("added", "user", "rules", "see", "ufw", "status"),
        )
        self.assertEqual(
            english_words("Added ПОДМЕНА user rules"),
            (
                "added",
                "подмена",
                "user",
                "rules",
            ),
        )

    def test_ufw_status_accepts_case_whitespace_and_punctuation(self):
        for output, expected in (
            (" STATUS - ACTIVE!\n", True),
            ("Status, inactive.\n", False),
            ("Status: active\nTo Action From\n", True),
        ):
            with self.subTest(output=output):
                self.assertIs(parse_ufw_status(output), expected)

    def test_ufw_status_rejects_missing_or_extra_semantics(self):
        for output in (
            "",
            "Status: unknown\n",
            "Status: inactive\nunexpected\n",
            "Status: active but degraded\n",
        ):
            with self.subTest(output=output):
                with self.assertRaises(ValueError):
                    parse_ufw_status(output)


if __name__ == "__main__":
    unittest.main()
