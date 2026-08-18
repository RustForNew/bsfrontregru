import unittest

from xhttp_setup.errors import ValidationError
from xhttp_setup.models import ExitDesired
from xhttp_setup.validate import (
    normalize_domain,
    validate_fingerprint,
    validate_remote_dir,
    validate_xhttp_path,
)


class ValidateTests(unittest.TestCase):
    def test_domain_is_idna_and_lowercase(self):
        self.assertEqual(normalize_domain("ПРИМЕР.РФ."), "xn--e1afmkfd.xn--p1ai")

    def test_single_label_is_rejected(self):
        with self.assertRaises(ValidationError):
            normalize_domain("localhost")

    def test_xhttp_path_rejects_regex_and_query_chars(self):
        for value in ("api/abcdefgh", "/api/a.*b", "/api/a?b", "/short"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validate_xhttp_path(value)

    def test_remote_dir_is_absolute_and_has_no_parent(self):
        self.assertEqual(
            validate_remote_dir("/var/www/u/data/www/example.org/"),
            "/var/www/u/data/www/example.org",
        )
        for value in ("relative/path", "/var/www/../root", "/var/www/a path"):
            with self.subTest(value=value), self.assertRaises(ValidationError):
                validate_remote_dir(value)

    def test_fingerprint_format(self):
        value = "SHA256:" + "A" * 43
        self.assertEqual(validate_fingerprint(value), value)
        with self.assertRaises(ValidationError):
            validate_fingerprint("SHA256:short")

    def test_unprivileged_exit_rejects_low_port(self):
        with self.assertRaises(ValidationError):
            ExitDesired(
                "203.0.113.10",
                443,
                "198.51.100.20",
                "/api/0123456789abcdef",
                "d342d11e-d424-4583-b36e-524ab1f0afa4",
            ).validate()


if __name__ == "__main__":
    unittest.main()
