# bsfrontregru

Настройка связки `сайт frontend → VLESS/XHTTP exit` с домашнего компьютера.
Мастер сам подключается к серверам по SSH/SFTP, применяет конфигурацию и выдаёт
клиентскую ссылку только после сквозной проверки.

## Скачать

- [Linux](https://github.com/RustForNew/bsfrontregru/releases/download/v0.3.0/xhttp-setup-0.3.0.pyz)
- [Windows 10/11 через WSL2](https://github.com/RustForNew/bsfrontregru/releases/download/v0.3.0/xhttp-setup-0.3.0-windows-wsl.zip)
- [Релиз v0.3.0 и SHA-256](https://github.com/RustForNew/bsfrontregru/releases/tag/v0.3.0)

## До запуска

Нужны:

- готовый сайт с доменом, A-записью, TLS/443, SFTP и точным `document root`;
- независимо полученный SHA-256 fingerprint SFTP-сервера;
- чистый Debian/Ubuntu exit с root SSH и уже активным UFW;
- независимо полученный SSH host-key fingerprint exit;
- измеренный исходящий IPv4 Apache (`FRONT_EGRESS_IP`), а не IP из DNS;
- при необходимости — доверенный российский VPS с root SSH и fingerprint.

Сайт, DNS и сертификат создаются заранее в панели хостинга. Мастер их не
создаёт и не меняет через ISPmanager.

## Linux

Требования: Python 3.10+, `curl` и OpenSSH client.

```bash
python3 xhttp-setup-0.3.0.pyz pc
```

## Windows

Это WSL2-пакет, не native EXE. Перед первым запуском обязательно установите
WSL2 с Ubuntu:

1. Откройте PowerShell от имени администратора.
2. Выполните `wsl --install -d Ubuntu` и перезагрузите компьютер.
3. Один раз откройте Ubuntu и создайте локальные имя и пароль. Это не данные
   root-сервера.
4. Скачайте ZIP и его `.sha256`, сверьте SHA-256.
5. Выберите в Проводнике «Извлечь всё».
6. Запустите `START-WINDOWS.cmd`.

Внутри WSL нужны Python 3.10+, `curl` и OpenSSH client. Путь к SSH-ключу
указывается внутри WSL, например `~/.ssh/id_ed25519`.

## Что вводить

Сначала exit: IP, SSH-порт, root-пароль или ключ, fingerprint, исходящий IP и
backend-порт. Затем frontend: домен, IP подключения клиента, IP A-записи,
`FRONT_EGRESS_IP`, TLS-режим, SFTP и `document root`. Российский SSH bridge —
необязательная опция для хостинга, доступного только из РФ.

Пароли вводятся интерактивно и не сохраняются в конфиги или аргументы команд.
При нестандартном firewall, Docker или неактивном UFW мастер останавливается без
изменений. Использование должно соответствовать правилам хостинга и закону.

Лицензия: MIT.
