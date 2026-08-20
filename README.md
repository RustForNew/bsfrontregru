# bsfrontregru

Настройка проверенной двухузловой схемы с домашнего компьютера:

```text
клиент → REG.RU frontend (TLS/443, XHTTP) → зарубежный Xray exit → интернет
```

Мастер подключается по закреплённым SSH/SFTP host keys, применяет exit и
frontend и выдаёт `client.vless` только после сквозной проверки через Xray core.
Российский SSH bridge нужен лишь для настройки при геоограничении и не входит в
рабочий маршрут.

## Скачать 0.4.1

- [Единая инструкция](https://github.com/RustForNew/bsfrontregru/releases/download/v0.4.1/INSTRUCTION.txt)
- [Windows через WSL2](https://github.com/RustForNew/bsfrontregru/releases/download/v0.4.1/xhttp-setup-0.4.1-windows-wsl.zip)
- [Linux](https://github.com/RustForNew/bsfrontregru/releases/download/v0.4.1/xhttp-setup-0.4.1.pyz)
- [Все файлы Release v0.4.1](https://github.com/RustForNew/bsfrontregru/releases/tag/v0.4.1)

Не запускайте сокращённую команду из сторонней инструкции. `INSTRUCTION.txt`
содержит подготовку чистого VPS, сайта REG.RU, безопасное измерение двух egress
IP, checksum-gated Linux-запуск и все ответы мастеру. Тот же файл лежит в ZIP.

## Windows

Нужен Windows 10 версии 2004 (build 19041)+ или Windows 11.

1. Скачайте Windows ZIP.
2. В Проводнике выберите «Извлечь все»; не запускайте файлы внутри архива.
3. Прочитайте единственный `INSTRUCTION.txt`.
4. Дважды нажмите `START-WINDOWS.cmd`.

При первом использовании инструкция проведёт через установку актуальной Ubuntu
в WSL2. В корне ZIP остаются только инструкция и стартовый CMD; папка
`_internal` служебная. Внешний `.zip.sha256` необязателен для запуска: launcher
сам проверяет встроенные `.pyz` и WSL-runner до выполнения.

## Linux

Для готового пути используйте Debian 12+ или Ubuntu 22.04+ с Python 3.10+.
Скачайте `.pyz`, его `.pyz.sha256` и выполните checksum-gated блок из
`INSTRUCTION.txt`. При несовпадении SHA-256 мастер не запустится.

## Что подготовить

- новый Debian 12+ / Ubuntu 22.04+ exit с прямым root SSH и активным clean UFW;
- независимо полученный SSH host-key fingerprint exit;
- готовый сайт: одна DNS A-запись без CDN/AAAA/CNAME, TLS/443, SFTP и точный
  `document root`;
- PHP в режиме `FastCGI (Apache)`, HSTS и HTTP→HTTPS выключены;
- независимо полученный SFTP host-key fingerprint REG.RU;
- exact leaf SHA-256 pin для self-signed сертификата;
- отдельно измеренные `EXIT_EGRESS_IP` и `FRONT_EGRESS_IP`;
- при необходимости — доверенный российский root SSH bridge с fingerprint.

Сайт, DNS и сертификат создаются заранее в ISPmanager. Мастер намеренно не
изменяет vhost через универсальный API и не угадывает egress IP по DNS/FTP.

## Важные границы

Правила REG.RU запрещают proxy-сервисы на виртуальном хостинге. Используйте эту
схему только после письменного разрешения провайдера либо там, где такой трафик
явно разрешён.

Пароли вводятся скрыто и не попадают в argv/environment/обычные файлы. Мастер не
отключает host-key verification, не включает `allowInsecure`, не меняет чужой
Docker/Xray/firewall и не выдаёт профиль после неуспешного E2E.

Для pinned TLS клиент обязан сохранять `pcs` / `pinnedPeerCertSha256`, XHTTP и
VLESS Encryption. Совместимость конкретного GUI и доступ через целевую SIM
проверяются отдельно; мастер доказывает маршрут через Xray core.

Лицензия: MIT.
