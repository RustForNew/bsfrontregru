import dataclasses
import unittest

from xhttp_setup.credential_parser import (
    ExitCredentials,
    RegRuCredentials,
    parse_exit_credentials,
    parse_regru_credentials,
)
from xhttp_setup.errors import ValidationError


PANEL_SECRET = "FakePanelSecret_42"
FTP_SECRET = "FakeFtpSecret_73"
MYSQL_SECRET = "FakeMysqlSecret_91"


def regru_block(*, panel_url: str = "https://vip999.hosting.reg.ru:1500/") -> str:
    return f"""
Логины и пароли

Доступ в панель управления хостингом

Логин:
u1234567

Пароль:
{PANEL_SECRET}

Ваша панель управления:
Ispmanager

Адрес панели управления хостингом:
[{panel_url}]({panel_url})

Как войти в панель управления хостингом?

Доступ к FTP

Логин:
u1234567

Пароль:
{FTP_SECRET}

IP-адрес сервера:
203.0.113.77

Как подключиться по FTP?

Доступ к MySQL

Логин:
u1234567_default

Пароль:
{MYSQL_SECRET}

Имя базы:
u1234567_default

Host:
localhost
"""


class ExitCredentialParserTests(unittest.TestCase):
    def test_parses_exact_three_line_block_and_preserves_password(self):
        credentials = parse_exit_credentials("8.8.8.8\nroot\n  fake secret  \n")

        self.assertEqual(credentials.ip, "8.8.8.8")
        self.assertEqual(credentials.username, "root")
        self.assertEqual(credentials.password, "  fake secret  ")

    def test_password_is_not_in_repr(self):
        credentials = ExitCredentials("8.8.8.8", "root", "DoNotPrintMe")

        self.assertNotIn("DoNotPrintMe", repr(credentials))

    def test_requires_literal_ipv4(self):
        with self.assertRaises(ValidationError):
            parse_exit_credentials("exit.example.test\nroot\nFakeSecret")

    def test_requires_root_user(self):
        secret = "NotLeakedSecret"
        with self.assertRaises(ValidationError) as caught:
            parse_exit_credentials(f"8.8.8.8\nadmin\n{secret}")

        self.assertNotIn(secret, str(caught.exception))

    def test_rejects_missing_or_extra_lines(self):
        invalid_blocks = (
            "8.8.8.8\nroot",
            "8.8.8.8\nroot\nFakeSecret\nextra",
            "8.8.8.8\n\nroot\nFakeSecret",
            "8.8.8.8\nroot\nFakeSecret\n\n",
        )
        for value in invalid_blocks:
            with self.subTest(value=value), self.assertRaises(ValidationError):
                parse_exit_credentials(value)

    def test_rejects_control_characters_and_oversize(self):
        with self.assertRaises(ValidationError):
            parse_exit_credentials("8.8.8.8\nroot\nFake\tSecret")
        with self.assertRaises(ValidationError):
            parse_exit_credentials("8.8.8.8\nroot\n" + "x" * 1025)

    def test_rejects_non_public_exit_ipv4(self):
        for address in ("127.0.0.1", "10.0.0.1", "203.0.113.42"):
            with self.subTest(address=address), self.assertRaises(ValidationError):
                parse_exit_credentials(f"{address}\nroot\nFakeSecret")


class RegRuCredentialParserTests(unittest.TestCase):
    def test_extracts_panel_and_ftp_and_ignores_mysql(self):
        credentials = parse_regru_credentials(regru_block())

        self.assertEqual(
            credentials,
            RegRuCredentials(
                panel_login="u1234567",
                panel_password=PANEL_SECRET,
                panel_url="https://vip999.hosting.reg.ru:1500/",
                ftp_login="u1234567",
                ftp_server_ip="203.0.113.77",
            ),
        )
        self.assertEqual(
            {field.name for field in dataclasses.fields(credentials)},
            {
                "panel_login",
                "panel_password",
                "panel_url",
                "ftp_login",
                "ftp_server_ip",
            },
        )

    def test_passwords_are_not_in_repr(self):
        credentials = parse_regru_credentials(regru_block())

        rendered = repr(credentials)
        self.assertNotIn(PANEL_SECRET, rendered)
        self.assertNotIn(FTP_SECRET, rendered)
        self.assertNotIn(MYSQL_SECRET, rendered)

    def test_ftp_password_is_not_retained(self):
        credentials = parse_regru_credentials(regru_block())

        self.assertFalse(hasattr(credentials, "ftp_password"))

    def test_accepts_inline_values_nbsp_and_plain_url(self):
        value = """
Доступ в панель управления хостингом
Логин:\u00a0u7654321
Пароль: FakePanel_1
Ваша панель управления: ISPmanager
Адрес панели управления: https://VIP999.HOSTING.REG.RU:1500/

Доступ\u00a0к\u00a0FTP
Логин: u7654321
Пароль: FakeFtp_2
IP‑адрес сервера: 198.51.100.28
"""

        credentials = parse_regru_credentials(value)

        self.assertEqual(credentials.panel_login, "u7654321")
        self.assertEqual(credentials.panel_url, "https://vip999.hosting.reg.ru:1500/")
        self.assertEqual(credentials.ftp_server_ip, "198.51.100.28")

    def test_accepts_label_punctuation_and_fullwidth_colon_without_changing_secret(
        self,
    ):
        secret = "FakePanelSecret_42!?。"
        block = regru_block().replace(PANEL_SECRET, secret, 1)
        replacements = {
            "Доступ в панель управления хостингом": (
                "Доступ в панель управления хостингом！"
            ),
            "Логин:": "Логин.：",
            "Пароль:": "Пароль…：",
            "Ваша панель управления:": "Ваша панель управления：",
            "Адрес панели управления хостингом:": (
                "Адрес панели управления хостингом.："
            ),
            "Доступ к FTP": "Доступ к FTP。",
            "IP-адрес сервера:": "IP-адрес сервера：",
        }
        for source, target in replacements.items():
            block = block.replace(source, target)

        credentials = parse_regru_credentials(block)

        self.assertEqual(credentials.panel_password, secret)
        self.assertEqual(credentials.panel_login, "u1234567")
        self.assertEqual(credentials.ftp_login, "u1234567")

    def test_accepts_markdown_link_with_text_label(self):
        block = regru_block().replace(
            "[https://vip999.hosting.reg.ru:1500/](https://vip999.hosting.reg.ru:1500/)",
            "[Открыть панель](https://vip999.hosting.reg.ru:1500/)",
        )

        self.assertEqual(
            parse_regru_credentials(block).panel_url,
            "https://vip999.hosting.reg.ru:1500/",
        )

    def test_rejects_markdown_with_conflicting_visible_url(self):
        block = regru_block().replace(
            "[https://vip999.hosting.reg.ru:1500/](https://vip999.hosting.reg.ru:1500/)",
            "[https://vip999.hosting.reg.ru:1500/](https://vip998.hosting.reg.ru:1500/)",
        )

        with self.assertRaises(ValidationError):
            parse_regru_credentials(block)

    def test_rejects_credentials_or_query_in_panel_url(self):
        invalid_urls = (
            "https://user:FakeUrlSecret@vip999.hosting.reg.ru:1500/",
            "https://user:FakeUrlSecret@vip999.hosting.reg.ru:not-a-port/",
            "https://vip999.hosting.reg.ru:1500/?session=FakeUrlSecret",
            "https://vip999.hosting.reg.ru:1500/?",
        )
        for url in invalid_urls:
            with self.subTest(url=url), self.assertRaises(ValidationError) as caught:
                parse_regru_credentials(regru_block(panel_url=url))
            self.assertNotIn("FakeUrlSecret", str(caught.exception))
            self.assertIsNone(caught.exception.__cause__)

    def test_requires_ispmanager_and_regru_panel_host_without_leaking_secrets(self):
        invalid_blocks = (
            regru_block().replace("Ispmanager", "cPanel", 1),
            regru_block().replace("Ispmanager", "ISPmanager:", 1),
            regru_block(panel_url="https://panel.example.test:1500/"),
            regru_block(panel_url="https://vip999.hosting.reg.ru:8443/"),
            regru_block(panel_url="https://vip999.hosting.reg.ru:1500/unexpected"),
        )
        for block in invalid_blocks:
            with self.subTest(), self.assertRaises(ValidationError) as caught:
                parse_regru_credentials(block)
            self.assertNotIn(PANEL_SECRET, str(caught.exception))
            self.assertNotIn(FTP_SECRET, str(caught.exception))

    def test_rejects_duplicate_or_conflicting_field(self):
        marker = f"Пароль:\n{PANEL_SECRET}"
        for duplicate in (marker, "Пароль:\nDifferentFakePanelSecret"):
            block = regru_block().replace(marker, f"{marker}\n{duplicate}", 1)
            with self.subTest(duplicate=duplicate), self.assertRaises(ValidationError):
                parse_regru_credentials(block)

    def test_rejects_duplicate_section(self):
        block = regru_block().replace("Доступ к FTP", "Доступ к FTP\nДоступ к FTP", 1)

        with self.assertRaises(ValidationError):
            parse_regru_credentials(block)

    def test_mysql_fields_are_scoped_and_duplicate_is_rejected(self):
        self.assertEqual(parse_regru_credentials(regru_block()).ftp_login, "u1234567")
        block = regru_block().replace(
            "Host:\nlocalhost", "Host:\nlocalhost\nHost:\n127.0.0.1"
        )

        with self.assertRaises(ValidationError):
            parse_regru_credentials(block)

    def test_requires_all_panel_and_ftp_fields(self):
        block = regru_block().replace("IP-адрес сервера:\n203.0.113.77", "", 1)

        with self.assertRaises(ValidationError):
            parse_regru_credentials(block)

    def test_ftp_server_must_be_ipv4(self):
        block = regru_block().replace("203.0.113.77", "ftp.example.test", 1)

        with self.assertRaises(ValidationError):
            parse_regru_credentials(block)

    def test_rejects_control_characters_and_bounded_input(self):
        with self.assertRaises(ValidationError):
            parse_regru_credentials(regru_block() + "\u202e")
        with self.assertRaises(ValidationError):
            parse_regru_credentials(regru_block() + "\n" + "x" * 2049)
        with self.assertRaises(ValidationError):
            parse_regru_credentials("\n".join(["ignored"] * 513))


if __name__ == "__main__":
    unittest.main()
