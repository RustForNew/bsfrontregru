# XHTTP Setup

Standalone-мастер для схемы из двух серверов:

```text
клиент -- VLESS/XHTTP + TLS :443 --> shared-hosting frontend
frontend -- HTTP/XHTTP --> зарубежный Xray exit --> интернет
```

На shared-hosting не ставятся Docker, Xray или фоновые сервисы: снаружи там
доступен только Apache сайта на 80/443. Xray устанавливается исключительно на
зарубежный exit.

TLS завершается на frontend. Внутренний VLESS payload дополнительно защищён
VLESS Encryption до выходного Xray. Внешнее плечо frontend → exit остаётся
HTTP, потому что обычный пользователь shared-hosting не может включить
`SSLProxyEngine` из `.htaccess`.

В клиентской ссылке `address` фиксируется на проверенном IPv4 frontend, а
домен отдельно задаётся как TLS SNI и XHTTP Host. Это исключает случайный уход
клиента на другой A/AAAA. По умолчанию сертификат проверяется системным CA и по
hostname. Для подтверждённого рабочего случая с чужим/неподходящим сертификатом
есть отдельный явный режим закрепления SHA-256 именно текущего leaf-сертификата.

## Что делает версия 0.3.0

- `pc`: с Linux/WSL-компьютера настраивает exit по закреплённому root SSH,
  затем применяет тот же frontend-процесс напрямую либо через доверенный
  российский root SSH bridge;
- `full`: настраивает изолированный Xray на текущем Linux VPS, затем существующий
  сайт frontend по SFTP и выполняет E2E-тест;
- `exit`: настраивает только выход и создаёт защищённый `handoff.json`;
- `front`: применяет `handoff.json` к существующему сайту и выполняет E2E-тест;
- `doctor`: read-only проверки DNS, TLS, маршрута, Xray и прав файлов;
- для frontend явно выбирает обычную публичную TLS-проверку либо закрепление
  текущего leaf-сертификата; `allowInsecure` не создаётся ни в одном режиме;
- опционально одним read-only POST-сеансом ISPmanager находит существующий сайт
  и берёт его фактический `docroot`; пароль и session id не сохраняются;
- ссылку `vless://` показывает и сохраняет только после успешного E2E-теста;
  тест принудительно очищает `NO_PROXY`, идёт через локальный SOCKS и сверяет
  фактический `ip=` с ожидаемым egress-IP выхода;
- меняет frontend в SFTP-транзакции; при сбое E2E/выдачи профиля
  возвращает свои файлы к pre-apply снимкам и не оставляет непроверенную
  клиентскую ссылку;
- при конкурентной правке сайта не перезаписывает её, а завершается fail-closed,
  сохраняя пути backups/quarantine и очищенную диагностику. Детали — в
  [`SECURITY.md`](SECURITY.md);
- меняет только собственный блок `.htaccess`; чужие правила сохраняет;
- сериализует front-apply lock-файлом; существующий немаркированный `state-dir`
  не захватывает и не меняет; локальные backups имеют `0700`, а remote backups
  получают скрытые имена со случайным 128-bit token;
- непосредственно перед SFTP-переключением повторно сверяет исходный файл и
  отменяет операцию, если сайт параллельно изменил другой процесс;
- не заменяет `index.html`, пока оператор явно не выберет нейтральную заглушку;
- не трогает чужой `xray.service`, Docker, BBR/sysctl и default policy firewall.

Выход работает отдельным непривилегированным сервисом
`xhttp-setup-xray.service`. Xray закреплён на stable `v26.3.27`; SHA-256 архива
и извлечённых файлов, тип файлов, owner и права проверяются при install/re-apply.
Между применениями systemd запускает binary из root-owned каталога; отдельной
проверки SHA перед каждым автоматическим restart сервиса нет.

## Чего мастер намеренно не делает

- не обходит антифрод, лимиты или блокировки хостинга;
- не ротирует домены для ухода от ограничений;
- не копирует и не reverse-proxy'ит RuFox или другой сторонний сайт;
- не включает безусловный `allowInsecure` и не отключает SSH host key;
- не создаёт vhost/Let's Encrypt через жёстко заданный ISPmanager API.

Последний пункт принципиален: поля изменения ISPmanager зависят от версии, тарифа и
плагинов провайдера. Неправильный универсальный запрос может изменить не тот
сайт. В 0.3.0 сайт, SSL-vhost и сертификат создаются заранее через ISPmanager.
В режиме `public` нужен сертификат публичного CA; в режиме `pinned` допускается
проверенный self-signed leaf. Мастер получает `document root` из списка сайтов
панели или принимает точное значение оператора.

Нейтральная заглушка оригинальна, явно сообщает, что не является RuFox, и
содержит обычную внешнюю ссылку `https://rufox.ru/`. Кнопка открывает настоящий
сайт; его содержимое не выдаётся за содержимое вашего домена.

## Обязательное предупреждение по REG.RU

Официальные правила REG.RU перечисляют proxy-сервисы среди запрещённых на
виртуальном хостинге. Настройка «аккуратно» не отменяет это правило и не даёт
гарантии от блокировки. Используйте схему только после письменного разрешения
провайдера либо на хостинге, где такой трафик явно разрешён.

Мастер показывает это как информационное сообщение, но не требует кодовой фразы
и не блокирует установку. Он также не содержит автоматической ротации доменов или
других механизмов обхода антифрода хостинга.

## Требования

- frontend: существующий сайт, A-запись без CDN-проксирования, TLS на 443, SFTP
  и Apache с `mod_rewrite`, `mod_proxy`, `mod_proxy_http` и разрешённым `[P]`;
  на проверенной конфигурации REG.RU также нужен включённый PHP в режиме
  `FastCGI (Apache)`, иначе nginx не передаёт XHTTP path в Apache и
  `.htaccess` не выполняется;
  предпочтителен валидный публичный сертификат, а pin-режим предназначен только
  для уже проверенного точного leaf-сертификата;
- exit: Debian/Ubuntu-подобный Linux, `systemd`, root/sudo, `x86_64` или
  `aarch64`, свободный TCP-порт выше 1024; для режима `pc` — прямой root SSH,
  уже активный UFW и доступная read-only команда `nft list ruleset`;
- оператор отдельно задаёт три IPv4-роли, перечисленные ниже;
- проверенный через панель/поддержку SHA-256 fingerprint SFTP-сервера;
- `curl`, `ssh`, `sftp`, `ssh-keyscan`, `ssh-keygen` на машине запуска.

`ssh-keyscan` сам по себе не подтверждает подлинность ключа. Мастер использует
его только для получения ключа и сравнивает результат с fingerprint, который
оператор получил независимо.

## Пошаговая установка

Полный порядок для проверенной split-схемы `exit напрямую → front с российского
bridge` находится в
[`docs/reg-ru-pinned-tls.txt`](docs/reg-ru-pinned-tls.txt). Там зафиксированы
публикация release, поля ISPmanager, получение SNI leaf pin, измерение реального
Apache egress, UFW до запуска Xray, перенос `handoff.json`, ответы мастеру и
финальная E2E-проверка.

Три IPv4 вводятся раздельно:

- `--client-connect-ip` — адрес подключения клиента и адрес в VLESS URI;
- `--dns-ipv4` — единственная A-запись frontend-домена;
- `--front-egress-ip` — source IPv4 Apache, измеренный на exit и разрешённый в
  firewall. Его нельзя выводить из первых двух адресов.

## Запуск с домашнего компьютера

Заранее подготовьте существующий сайт, DNS A-запись, TLS/443, SFTP и точный
document root. Серверы вручную открывать не нужно.

Linux:

```bash
python3 xhttp-setup-0.3.0.pyz pc
```

Windows 10/11:

1. Один раз установите WSL2: `wsl --install -d Ubuntu`, затем перезагрузитесь.
2. Распакуйте `xhttp-setup-0.3.0-windows-wsl.zip`.
3. Запустите `START-WINDOWS.cmd` двойным кликом.

Windows-пакет сверяет SHA-256 вложенного `.pyz` и запускает тот же мастер внутри
WSL2. Native Windows без WSL не поддерживается: отдельный SSH-транспорт для него
не подменяет проверенный Linux-путь.

Мастер запросит root SSH выхода, независимо проверенный host-key fingerprint,
публичный/исходящий IP выхода, backend-порт и фактически измеренный egress IPv4
Apache frontend. Затем вводятся домен, IP сайта, TLS и SFTP. Frontend запускается
прямо с этого компьютера или, если хостинг принимает подключения только из РФ,
через доверенный российский root SSH bridge. Bridge участвует только в настройке,
не в рабочем трафике.

Порядок применения: remote UFW → неизменённый серверный `exit` → неизменённый
серверный `front` → обязательный E2E. `FRONT_EGRESS_IP` нельзя угадывать по DNS
или IP сайта: используйте только измеренное значение из ручного runbook.

## Запуск из исходников

```bash
python3 -m xhttp_setup --help
sudo python3 -m xhttp_setup
```

Меню:

```text
1. Полная установка: frontend + выход на текущем VPS
2. Только выход на текущем VPS
3. Только frontend по готовому handoff.json
4. Doctor
5. Установка exit + frontend с персонального компьютера (Linux/WSL)
```

`full` запускается непосредственно на выходном VPS. Если shared-hosting не
принимает SFTP с иностранного IP, используйте режимы раздельно: `exit` на VPS,
затем безопасно перенесите `/var/lib/xhttp-setup/handoff.json` и запустите
`front` с Linux-машины/WSL, чей IP разрешён хостингом. Не пересылайте handoff в
открытом виде: в нём находится клиентский материал доступа.

## Firewall

В режиме `pc` поддерживается только прямой root SSH к Debian/Ubuntu с уже
активным UFW и без Docker/containerd, `nftables.service` или custom nftables.
Мастер добавляет точный allow от `FRONT_EGRESS_IP/32` и следующий за ним deny
backend-порта, затем открывает новую SSH-сессию для проверки. Он не включает и
не отключает UFW, не меняет default policy, SSH-правила или cloud firewall; при
неоднозначном состоянии прекращает работу.

Локальные режимы `full` и `exit` по-прежнему только создают:

```text
/var/lib/xhttp-setup/firewall-plan.txt
```

Файл содержит только allow `/32` и deny для backend. Он не настраивает SSH, не
включает UFW и не является shell-скриптом. Перед выдачей ссылки мастер требует
подтвердить, что порядок правил проверен и backend недоступен с другого адреса.

## Неинтерактивный plan/apply

Plan по умолчанию ничего не пишет:

```bash
xhttp-setup exit \
  --public-address 203.0.113.10 \
  --front-egress-ip 198.51.100.20 \
  --port 8083
```

По умолчанию ожидаемый egress-IP выхода равен `--public-address`; для VPS с NAT
задайте его через `--expected-egress-ip`.

UUID и случайный XHTTP path создаются автоматически. Если нужен заранее
подготовленный UUID, передайте путь через `--client-id-file`; файл должен иметь
права `0600`. UUID намеренно не принимается напрямую в argv.

Применение требует одновременно `--apply` и точное подтверждение:

```bash
sudo xhttp-setup exit ... --apply --confirm 'APPLY EXIT'
```

Для отдельного шага frontend укажите обе его IP-роли явно:

```bash
xhttp-setup front \
  --handoff /secure/handoff.json \
  --domain front.example.org \
  --client-connect-ip 198.51.100.20 \
  --dns-ipv4 192.0.2.30 \
  --sftp-host sftp.example.org \
  --sftp-user site_user \
  --document-root /var/www/site \
  --fingerprint 'SHA256:...'
```

Для явного pin-режима к той же команде добавляются:

```bash
  --tls-mode pinned \
  --tls-cert-sha256 '0123456789abcdef...64 hex symbols...'
```

Без этих параметров остаётся `--tls-mode public`. Pin — публичный fingerprint,
поэтому его допустимо передавать как аргумент; UUID, VLESS Encryption material и
пароли по-прежнему нельзя помещать в argv.

Старый `--front-public-ip` временно поддерживается, но подставляет один адрес
сразу в обе роли и поэтому не подходит для схем, где они различаются.

Обычный password-auth вводится скрыто из TTY. В bridge-режиме SFTP-пароль
передаётся одной ограниченной строкой через stdin уже закреплённого SSH; он не
помещается в argv, environment или файл. Для иной автоматизации используйте
отдельный SSH-ключ и заранее закреплённый fingerprint.

## Сборка release

```bash
python3 scripts/build.py
python3 scripts/build_windows_bundle.py
python3 -m unittest discover -s tests -v
```

Артефакты появятся в `dist/`:

```text
xhttp-setup-0.3.0.pyz
xhttp-setup-0.3.0.pyz.sha256
xhttp-setup-0.3.0-windows-wsl.zip
xhttp-setup-0.3.0-windows-wsl.zip.sha256
```

GitHub workflow публикует только tag вида `vX.Y.Z`. В репозитории включите
`Settings → General → Releases → immutable releases` и ruleset, запрещающий
изменение/удаление release tags.

Безопасный download-блок для своего README приведён в
[`docs-release-install.txt`](docs-release-install.txt). Перед публикацией
замените `OWNER/REPOSITORY` на имя своего репозитория. Код из `main` через
`curl | bash` проект не использует.

## Файлы на exit

```text
/opt/xhttp-setup/xray/v26.3.27/       закреплённый Xray и manifest
/etc/xhttp-setup/xray.json            managed-конфиг, 0640
/var/lib/xhttp-setup/secrets.json     decryption/encryption, 0600
/var/lib/xhttp-setup/handoff.json     данные для frontend, 0600
/var/lib/xhttp-setup/firewall-plan.txt
/etc/systemd/system/xhttp-setup-xray.service
```

Логи сервиса:

```bash
journalctl -u xhttp-setup-xray --since today
```

После отдельной проверки и истечения вашего окна rollback старые скрытые
`.xhttp-backup-*` в document root можно удалить вручную по точным именам из
результата запуска. Мастер сам retention не выполняет и чужие backups не трогает.

## Ограничения MVP и статус live-проверки

- автоматический rollback покрывает неуспешный запуск managed systemd-сервиса и
  frontend-транзакцию вплоть до подтверждения firewall, E2E и записи профиля;
  отдельной команды rollback после уже успешной установки в 0.3.0 ещё нет;
- выдача Let's Encrypt, DNS propagation и capability-driven ISPmanager adapter
  оставлены для следующей версии;
- Windows-пакет требует WSL2; native Windows без WSL не поддерживается;
- `full` не может технически доказать внешний firewall с того же exit VPS,
  поэтому требует операторскую проверку из другой сети;
- успешный HTTP-код XHTTP path не доказывает туннель; финальная проверка запускает
  временный Xray-клиент и реальный SOCKS-запрос.
- split-порядок `exit напрямую → front с российского bridge`, password SFTP,
  pinned TLS, ручной UFW `/32` и Xray E2E проверены на чистом развёртывании;
- PC-orchestrator, remote UFW и bridge-транспорт покрыты unit-тестами, но как
  единый автоматический путь отдельно live не проверены. Они повторно используют
  серверные `exit`, `front` и E2E, подтверждённые прежним сквозным запуском;
- optional MSS-профиль не используется режимом `pc`, остаётся runtime-only и не
  обещает persistence после reboot.

Результаты разбора исходного примера, чистого live-развёртывания и оставшиеся
непроверенные границы зафиксированы в
[`docs/reference-audit-2026-08-19.md`](docs/reference-audit-2026-08-19.md).

## Технические источники

- Xray stable v26.3.27: <https://github.com/XTLS/Xray-core/releases/tag/v26.3.27>
- XHTTP, режимы и URI packet-up: <https://github.com/XTLS/Xray-core/discussions/4113>
- VLESS Encryption / `xray vlessenc`: <https://xtls.github.io/en/document/command.html#xray-vlessenc>
- TLS/SNI/fingerprint: <https://xtls.github.io/en/config/transports/tls.html>
- официальный VLESS URI-параметр `pcs`: <https://github.com/XTLS/Xray-core/discussions/716>
- ограничение pinning: закреплять leaf, не CA: <https://github.com/XTLS/Xray-core/security/advisories/GHSA-5wf9-h793-w73c>
- Apache RewriteRule `[P]`: <https://httpd.apache.org/docs/2.4/rewrite/flags.html#flag_p>
- ISPmanager API: <https://www.ispmanager.com/docs/ispmanager/ispmanager-api>
- Ограничения виртуального хостинга REG.RU:
  <https://help.reg.ru/support/hosting/zakaz-hostinga-rabota-s-uslugoy/sovety-po-vyboru-tarifa-hostinga>
- GitHub immutable releases:
  <https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases>
