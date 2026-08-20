import io
import os
import time
import unittest
from unittest import mock

from xhttp_setup.errors import InstallerError, ValidationError
from xhttp_setup.hidden_input import read_hidden_block


if os.name == "posix":  # pragma: no branch - imports are unavailable on Windows
    import errno
    import pty
    import select
    import signal
    import termios
    import traceback


PROMPT_MARKER = "Для завершения".encode()


@unittest.skipUnless(os.name == "posix", "requires a POSIX pseudo-terminal")
class HiddenInputPtyTests(unittest.TestCase):
    def _read_available(self, master_fd: int) -> bytes:
        chunks: list[bytes] = []
        while True:
            try:
                chunk = os.read(master_fd, 4096)
            except BlockingIOError:
                break
            except OSError as exc:
                if exc.errno == errno.EIO:
                    break
                raise
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)

    def _read_until(self, master_fd: int, marker: bytes, deadline: float) -> bytes:
        transcript = bytearray()
        while marker not in transcript:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.fail("hidden input prompt did not appear")
            readable, _, _ = select.select([master_fd], [], [], min(remaining, 0.1))
            if not readable:
                continue
            transcript.extend(self._read_available(master_fd))
        return bytes(transcript)

    def _write_payload(self, master_fd: int, payload: bytes, deadline: float) -> None:
        offset = 0
        while offset < len(payload):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.fail("timed out while sending pseudo-terminal input")
            _, writable, _ = select.select([], [master_fd], [], min(remaining, 0.1))
            if not writable:
                continue
            try:
                written = os.write(master_fd, payload[offset : offset + 4096])
            except BlockingIOError:
                continue
            except OSError as exc:
                if exc.errno == errno.EIO:
                    return
                raise
            offset += written

    def _finish_child(
        self,
        pid: int,
        master_fd: int,
        transcript: bytes,
        deadline: float,
    ) -> bytes:
        output = bytearray(transcript)
        status: int | None = None
        while status is None:
            output.extend(self._read_available(master_fd))
            finished_pid, candidate = os.waitpid(pid, os.WNOHANG)
            if finished_pid == pid:
                status = candidate
                break
            if time.monotonic() >= deadline:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
                self.fail("hidden input child timed out")
            select.select([master_fd], [], [], 0.05)

        output.extend(self._read_available(master_fd))
        self.assertTrue(os.WIFEXITED(status), bytes(output))
        self.assertEqual(os.WEXITSTATUS(status), 0, bytes(output))
        return bytes(output)

    def _run_case(self, child_action, payload: bytes) -> bytes:
        pid, master_fd = pty.fork()
        if pid == 0:
            try:
                child_action()
            except BaseException:
                traceback.print_exc()
                os._exit(97)
            os._exit(0)

        os.set_blocking(master_fd, False)
        deadline = time.monotonic() + 8
        try:
            transcript = self._read_until(master_fd, PROMPT_MARKER, deadline)
            self._write_payload(master_fd, payload, deadline)
            return self._finish_child(pid, master_fd, transcript, deadline)
        finally:
            os.close(master_fd)

    def test_secret_is_not_echoed_and_echo_is_restored(self):
        secret = "VERY_SECRET_MARKER_42"

        def child_action() -> None:
            echo_before = bool(termios.tcgetattr(0)[3] & termios.ECHO)
            result = read_hidden_block("Данные теста")
            echo_after = bool(termios.tcgetattr(0)[3] & termios.ECHO)
            if result != f"first line\n{secret}" or not echo_before or not echo_after:
                raise AssertionError("unexpected hidden input result or terminal state")
            os.write(1, b"SUCCESS_AND_ECHO_RESTORED\n")

        transcript = self._run_case(
            child_action,
            f"first line\n{secret}\nГОТОВО\n".encode(),
        )

        self.assertIn(b"SUCCESS_AND_ECHO_RESTORED", transcript)
        self.assertNotIn(secret.encode(), transcript)
        self.assertNotIn(b"first line", transcript)

    def test_crlf_cyrillic_terminator_and_pasted_suffix_are_safe(self):
        suffix = "MUST_NOT_REACH_NEXT_PROMPT"

        def child_action() -> None:
            result = read_hidden_block("Данные выхода", minimum_data_lines=3)
            if result != "8.8.8.8\nroot\nГОТОВО":
                raise AssertionError("the third line was mistaken for a terminator")
            readable, _, _ = select.select([0], [], [], 0.25)
            if readable:
                raise AssertionError(
                    "pasted suffix remained in the terminal input queue"
                )
            os.write(1, b"CRLF_AND_SUFFIX_OK\n")

        transcript = self._run_case(
            child_action,
            (f"8.8.8.8\r\nroot\r\nГОТОВО\r\nГОТОВО\r\n{suffix}\r\n").encode(),
        )

        self.assertIn(b"CRLF_AND_SUFFIX_OK", transcript)
        self.assertNotIn(suffix.encode(), transcript)

    def test_line_limit_rejects_input_and_restores_echo(self):
        def child_action() -> None:
            try:
                read_hidden_block("Слишком длинная строка")
            except ValidationError as exc:
                if "слишком длинная" not in str(exc):
                    raise
            else:
                raise AssertionError("oversize line was accepted")
            if not termios.tcgetattr(0)[3] & termios.ECHO:
                raise AssertionError("echo was not restored after a limit error")
            os.write(1, b"LINE_LIMIT_AND_ECHO_OK\n")

        transcript = self._run_case(child_action, b"x" * 8193)

        self.assertIn(b"LINE_LIMIT_AND_ECHO_OK", transcript)

    def test_data_line_limit_is_enforced(self):
        def child_action() -> None:
            try:
                read_hidden_block("Слишком много строк")
            except ValidationError as exc:
                if "слишком много строк" not in str(exc):
                    raise
            else:
                raise AssertionError("too many lines were accepted")
            os.write(1, b"LINE_COUNT_LIMIT_OK\n")

        transcript = self._run_case(child_action, b"x\n" * 257)

        self.assertIn(b"LINE_COUNT_LIMIT_OK", transcript)

    def test_total_byte_limit_is_enforced(self):
        def child_action() -> None:
            try:
                read_hidden_block("Слишком большой блок")
            except ValidationError as exc:
                if "размер" not in str(exc):
                    raise
            else:
                raise AssertionError("oversize block was accepted")
            if not termios.tcgetattr(0)[3] & termios.ECHO:
                raise AssertionError("echo was not restored after a total-size error")
            os.write(1, b"TOTAL_LIMIT_AND_ECHO_OK\n")

        payload = (b"x" * 256 + b"\n") * 256
        transcript = self._run_case(child_action, payload)

        self.assertIn(b"TOTAL_LIMIT_AND_ECHO_OK", transcript)

    def test_ctrl_c_restores_echo(self):
        def child_action() -> None:
            try:
                read_hidden_block("Прерывание")
            except KeyboardInterrupt:
                pass
            else:
                raise AssertionError("Ctrl-C did not interrupt hidden input")
            if not termios.tcgetattr(0)[3] & termios.ECHO:
                raise AssertionError("echo was not restored after Ctrl-C")
            os.write(1, b"CTRL_C_AND_ECHO_OK\n")

        transcript = self._run_case(child_action, b"\x03")

        self.assertIn(b"CTRL_C_AND_ECHO_OK", transcript)

    def test_quit_and_suspend_control_bytes_cannot_bypass_restoration(self):
        for control_byte, marker in (
            (b"\x1c", b"CTRL_QUIT_DISABLED_AND_ECHO_OK"),
            (b"\x1a", b"CTRL_SUSPEND_DISABLED_AND_ECHO_OK"),
        ):
            with self.subTest(control_byte=control_byte):

                def child_action() -> None:
                    try:
                        read_hidden_block("Сигнальный байт")
                    except ValidationError:
                        pass
                    else:
                        raise AssertionError("signal control byte was accepted")
                    if not termios.tcgetattr(0)[3] & termios.ECHO:
                        raise AssertionError("echo was not restored")
                    os.write(1, marker + b"\n")

                transcript = self._run_case(child_action, control_byte)
                self.assertIn(marker, transcript)


class HiddenInputValidationTests(unittest.TestCase):
    def test_non_tty_input_is_rejected_before_opening_dev_tty(self):
        with (
            mock.patch("xhttp_setup.hidden_input.sys.stdin", io.StringIO()),
            mock.patch("xhttp_setup.hidden_input.sys.stdout", io.StringIO()),
            self.assertRaises(InstallerError) as caught,
        ):
            read_hidden_block("Данные")

        self.assertNotIn("secret", str(caught.exception).casefold())

    def test_public_parameters_reject_control_characters_and_bad_minimum(self):
        with self.assertRaises(ValidationError):
            read_hidden_block("Небезопасное\x1bназвание")
        with self.assertRaises(ValidationError):
            read_hidden_block("Данные", terminator="ГОТОВО\nЕЩЁ")
        for invalid in (True, 0, 257):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                read_hidden_block("Данные", minimum_data_lines=invalid)


if __name__ == "__main__":
    unittest.main()
