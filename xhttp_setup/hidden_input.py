from __future__ import annotations

import os
import sys
import unicodedata
from types import ModuleType

from .errors import InstallerError, ValidationError


_MAX_TOTAL_BYTES = 64 * 1024
_MAX_DATA_LINES = 256
_MAX_LINE_BYTES = 8192
_MAX_LABEL_BYTES = 512

try:  # pragma: no cover - the POSIX branch is exercised on Linux/WSL
    import termios as _termios
except ImportError:  # pragma: no cover - Windows has no termios
    _termios: ModuleType | None = None


def _require_safe_text(value: str, *, name: str, allow_empty: bool = False) -> None:
    if not isinstance(value, str) or (not value and not allow_empty):
        raise ValidationError(f"{name} не задан")
    for character in value:
        if character in "\r\n\v\f\x85\u2028\u2029" or unicodedata.category(
            character
        ) in {"Cc", "Cf", "Cs"}:
            raise ValidationError(f"{name} содержит управляющие символы")


def _stream_is_tty(stream: object) -> bool:
    try:
        isatty = getattr(stream, "isatty")
        fileno = getattr(stream, "fileno")
        return bool(isatty()) and os.isatty(fileno())
    except (AttributeError, OSError, ValueError):
        return False


def _write_all(fd: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        try:
            written = os.write(fd, value[offset:])
        except InterruptedError:
            continue
        if written <= 0:
            raise InstallerError("Не удалось вывести подсказку скрытого ввода")
        offset += written


def _hidden_attributes(
    original: list[object], termios: ModuleType, disabled_control: bytes
) -> list[object]:
    hidden = original.copy()
    hidden[6] = original[6].copy()  # type: ignore[union-attr]

    # Receive CR and LF unchanged so both Unix LF and pasted Windows CRLF can be
    # handled without inventing empty lines.  Keep ISIG enabled for Ctrl-C.
    for flag_name in ("ICRNL", "INLCR", "IGNCR", "ISTRIP", "IUCLC", "IXON", "IXOFF"):
        hidden[0] &= ~getattr(termios, flag_name, 0)  # type: ignore[operator]

    for flag_name in (
        "ECHO",
        "ECHOE",
        "ECHOK",
        "ECHONL",
        "ECHOPRT",
        "ECHOCTL",
        "ECHOKE",
    ):
        hidden[3] &= ~getattr(termios, flag_name, 0)  # type: ignore[operator]
    hidden[3] &= ~termios.ICANON  # type: ignore[operator]
    hidden[6][termios.VMIN] = 1  # type: ignore[index]
    hidden[6][termios.VTIME] = 0  # type: ignore[index]
    # Keep VINTR/Ctrl-C so Python can restore the terminal in ``finally``.
    # Disable terminal-generated quit/suspend signals, which could otherwise
    # stop the process before Python has a chance to restore echo/canonical mode.
    for name in ("VQUIT", "VSUSP", "VDSUSP"):
        index = getattr(termios, name, None)
        if index is not None:
            hidden[6][index] = disabled_control  # type: ignore[index]
    return hidden


def _decode_line(value: bytes) -> str:
    try:
        line = value.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        # Do not retain the rejected byte buffer as an exception cause.
        raise ValidationError("Скрытый блок должен быть в UTF-8") from None
    _require_safe_text(line, name="Строка скрытого блока", allow_empty=True)
    return line


def _read_block(
    fd: int,
    *,
    minimum_data_lines: int,
    terminator: str,
    termios: ModuleType,
) -> str:
    data_lines: list[str] = []
    current_line = bytearray()
    total_bytes = 0
    skip_lf_after_cr = False

    while True:
        try:
            chunk = os.read(fd, 1)
        except InterruptedError:
            continue
        if not chunk:
            raise InstallerError("Скрытый ввод завершён до строки окончания")

        total_bytes += 1
        if total_bytes > _MAX_TOTAL_BYTES:
            raise ValidationError("Скрытый блок превышает допустимый размер")

        byte = chunk[0]
        if skip_lf_after_cr:
            skip_lf_after_cr = False
            if byte == 0x0A:
                continue

        if byte in (0x0A, 0x0D):
            skip_lf_after_cr = byte == 0x0D
            line = _decode_line(bytes(current_line))
            current_line.clear()

            # The terminator is data until all mandatory data lines precede it.
            # This permits, for example, an exit password literally equal to it.
            if line == terminator and len(data_lines) >= minimum_data_lines:
                termios.tcflush(fd, termios.TCIFLUSH)
                _write_all(fd, "Блок принят.\n".encode("utf-8"))
                return "\n".join(data_lines)

            if len(data_lines) >= _MAX_DATA_LINES:
                raise ValidationError("В скрытом блоке слишком много строк")
            data_lines.append(line)
            continue

        # In non-canonical mode Ctrl-D arrives as a byte rather than read(2)
        # returning EOF.  Treat it as an incomplete block, without exposing data.
        if byte == 0x04:
            raise InstallerError("Скрытый ввод завершён до строки окончания")
        if byte == 0x00 or byte < 0x20 or byte == 0x7F:
            raise ValidationError("Скрытый блок содержит управляющие символы")

        current_line.append(byte)
        if len(current_line) > _MAX_LINE_BYTES:
            raise ValidationError("Строка скрытого блока слишком длинная")


def read_hidden_block(
    label: str,
    *,
    minimum_data_lines: int = 1,
    terminator: str = "ГОТОВО",
) -> str:
    """Read a bounded multiline secret from the controlling POSIX terminal.

    Input is never read through ``sys.stdin``: reading ``/dev/tty`` one byte at
    a time avoids TextIO read-ahead consuming answers meant for later prompts.
    Echo stays disabled for the whole block and is restored on every exit path.
    """

    _require_safe_text(label, name="Название скрытого блока")
    if len(label.encode("utf-8")) > _MAX_LABEL_BYTES:
        raise ValidationError("Название скрытого блока слишком длинное")
    _require_safe_text(terminator, name="Строка окончания")
    if len(terminator.encode("utf-8")) > _MAX_LINE_BYTES:
        raise ValidationError("Строка окончания слишком длинная")
    if (
        isinstance(minimum_data_lines, bool)
        or not isinstance(minimum_data_lines, int)
        or not 1 <= minimum_data_lines <= _MAX_DATA_LINES
    ):
        raise ValidationError("Недопустимое минимальное число строк")

    if os.name != "posix" or _termios is None:
        raise InstallerError("Скрытая вставка доступна только в Linux/WSL")
    if not _stream_is_tty(sys.stdin) or not _stream_is_tty(sys.stdout):
        raise InstallerError("Скрытая вставка требует интерактивный терминал")

    flags = os.O_RDWR | getattr(os, "O_NOCTTY", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        tty_fd = os.open("/dev/tty", flags)
    except OSError as exc:
        raise InstallerError("Не удалось открыть управляющий терминал") from exc

    original: list[object] | None = None
    restore_error: BaseException | None = None
    try:
        if not os.isatty(tty_fd):
            raise InstallerError("Управляющий терминал недоступен")
        try:
            original = _termios.tcgetattr(tty_fd)
            disabled_value = os.fpathconf(tty_fd, "PC_VDISABLE")
            if not isinstance(disabled_value, int) or not 0 <= disabled_value <= 255:
                raise OSError("invalid PC_VDISABLE")
            hidden = _hidden_attributes(
                original,
                _termios,
                bytes((disabled_value,)),
            )
            _termios.tcsetattr(tty_fd, _termios.TCSANOW, hidden)
        except (OSError, ValueError, _termios.error) as exc:
            raise InstallerError("Не удалось включить скрытый ввод") from exc

        instructions = (
            f"{label}\n"
            "Вставьте блок: ввод полностью скрыт. "
            f"Для завершения введите отдельной строкой {terminator}.\n"
        )
        _write_all(tty_fd, instructions.encode("utf-8"))
        result = _read_block(
            tty_fd,
            minimum_data_lines=minimum_data_lines,
            terminator=terminator,
            termios=_termios,
        )
    finally:
        exception_active = sys.exc_info()[0] is not None
        if original is not None:
            # On validation errors or Ctrl-C, discard any remainder while echo
            # is still off so a caller retry cannot consume or reveal it.
            try:
                _termios.tcflush(tty_fd, _termios.TCIFLUSH)
            except (OSError, _termios.error):
                pass
            try:
                _termios.tcsetattr(tty_fd, _termios.TCSANOW, original)
            except (OSError, _termios.error) as exc:
                if not exception_active:
                    restore_error = exc
        os.close(tty_fd)

    if restore_error is not None:
        raise InstallerError(
            "Не удалось восстановить настройки терминала"
        ) from restore_error
    return result
