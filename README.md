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
клиента на другой A/AAAA, сохраняя строгую проверку сертификата.

## Что делает версия 0.1.0

- `full`: настраивает изолированный Xray на текущем Linux VPS, затем существующий
  сайт frontend по SFTP и выполняет E2E-тест;
- `exit`: настраивает только выход и создаёт защищённый `handoff.json`;
- `front`: применяет `handoff.json` к существующему сайту и выполняет E2E-тест;
- `doctor`: read-only проверки DNS, TLS, маршрута, Xray и прав файлов;
- опционально одним read-only POST-сеансом ISPmanager находит существующий сайт
  и берёт его фактический `docroot`; пароль и session id не сохраняются;
- ссылку `vless://` показывает и сохраняет только после успешного E2E-теста;
  тест принудительно очищает `NO_PROXY`, идёт через локальный SOCKS и сверяет
  фактический `ip=` с ожидаемым egress-IP выхода;
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
- не отключает проверку TLS и SSH host key;
- не создаёт vhost/Let's Encrypt через жёстко заданный ISPmanager API.

Последний пункт принципиален: поля изменения ISPmanager зависят от версии, тарифа и
плагинов провайдера. Неправильный универсальный запрос может изменить не тот
сайт. В 0.1.0 сайт и публичный сертификат создаются заранее через ISPmanager,
а мастер получает `document root` из списка сайтов панели.

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

- frontend: существующий сайт, A-запись без CDN-проксирования, валидный
  публичный сертификат на 443, SFTP и Apache с `mod_rewrite`, `mod_proxy`,
  `mod_proxy_http` и разрешённым `[P]`;
- exit: Debian/Ubuntu-подобный Linux, `systemd`, root/sudo, `x86_64` или
  `aarch64`, свободный TCP-порт выше 1024;
- оператор различает три IPv4: адрес подключения клиента, DNS A домена и
  фактический исходящий адрес shared-hosting. Они могут различаться;
- проверенный через панель/поддержку SHA-256 fingerprint SFTP-сервера;
- `curl`, `ssh`, `sftp`, `ssh-keyscan`, `ssh-keygen` на машине запуска.

`ssh-keyscan` сам по себе не подтверждает подлинность ключа. Мастер использует
его только для получения ключа и сравнивает результат с fingerprint, который
оператор получил независимо.

## Подготовка frontend

1. Создайте отдельный FQDN, например `front.example.org`.
2. Направьте A-запись прямо на IP сайта shared-hosting. Не включайте CDN proxy.
3. В ISPmanager создайте сайт без PHP, назначьте этот FQDN и выпустите
   Let's Encrypt.
4. Проверьте `https://front.example.org/` обычным браузером без предупреждений.
5. Отдельно проверьте с целевой SIM/оператора, что нужный белый доступ действует
   именно на TCP 443. Работа схемы на 80 не доказывает работу zero-rating на 443.
6. В списке сайтов скопируйте фактический `document root`; не составляйте путь
   вручную.
7. Получите у провайдера SSH/SFTP host-key fingerprint.

Три адреса вводятся независимо:

- `--client-connect-ip` — адрес в VLESS URI. Именно к нему выполняется TLS
  соединение с SNI и `Host` вашего домена;
- `--dns-ipv4` — единственная ожидаемая A-запись домена для сайта и ACME;
- `--front-egress-ip` — source IPv4, который выходной VPS реально видит у
  проксированных запросов и разрешает в firewall.

Назначенный ISPmanager IP сайта может не совпадать с первыми двумя адресами,
например при общей или anycast-инфраструктуре. Это выводится как примечание, а
не считается ошибкой: мастер отдельно проверяет DNS и валидный сертификат на
фактическом адресе подключения клиента.

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
```

`full` запускается непосредственно на выходном VPS. Если shared-hosting не
принимает SFTP с иностранного IP, используйте режимы раздельно: `exit` на VPS,
затем безопасно перенесите `/var/lib/xhttp-setup/handoff.json` и запустите
`front` с Linux-машины/WSL, чей IP разрешён хостингом. Не пересылайте handoff в
открытом виде: в нём находится клиентский материал доступа.

## Firewall

Мастер не включает UFW и не меняет default policy: автоматическое включение
может отрезать SSH или конфликтовать с Docker/nftables. После `exit` создаётся:

```text
/var/lib/xhttp-setup/firewall-plan.txt
```

Там находятся точные правила для введённого egress-IP. Перед выдачей ссылки
мастер требует подтвердить, что backend-порт проверен извне и не открыт другим
адресам. Если egress-IP хостинга ротируется, `/32` безопаснее, но связь может
сломаться; широкий CIDR устойчивее, но открывает backend всему пулу провайдера.

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

Старый `--front-public-ip` временно поддерживается, но подставляет один адрес
сразу в обе роли и поэтому не подходит для схем, где они различаются.

Password-auth разрешён только в интерактивном терминале. Для автоматизации
используйте отдельный SSH-ключ и заранее закреплённый fingerprint.

## Сборка release

```bash
python3 scripts/build.py
python3 -m unittest discover -s tests -v
```

Артефакты появятся в `dist/`:

```text
xhttp-setup-0.1.0.pyz
xhttp-setup-0.1.0.pyz.sha256
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

## Ограничения MVP

- автоматический rollback покрывает неуспешный запуск managed systemd-сервиса и
  непосредственный сбой/5xx после SFTP-переключения; отдельной команды rollback
  в 0.1.0 ещё нет;
- выдача Let's Encrypt, DNS propagation и capability-driven ISPmanager adapter
  оставлены для следующей версии;
- Windows без WSL не поддерживается для применения, хотя pure plan/help и тесты
  собираются;
- `full` не может технически доказать внешний firewall с того же exit VPS,
  поэтому требует операторскую проверку из другой сети;
- успешный HTTP-код XHTTP path не доказывает туннель; финальная проверка запускает
  временный Xray-клиент и реальный SOCKS-запрос.
- внутренние API `remote_exit` и `exit_network` покрыты unit-тестами, но пока не
  подключены к основному меню: сначала нужен clean-host live-тест. MSS в
  optional-профиле до этого теста только runtime, без обещания persistence после
  reboot.

Read-only разбор предоставленного живого примера и граница между подтверждённым
и ожидающим clean-host теста зафиксированы в
[`docs/reference-audit-2026-08-19.md`](docs/reference-audit-2026-08-19.md).

## Технические источники

- Xray stable v26.3.27: <https://github.com/XTLS/Xray-core/releases/tag/v26.3.27>
- XHTTP, режимы и URI packet-up: <https://github.com/XTLS/Xray-core/discussions/4113>
- VLESS Encryption / `xray vlessenc`: <https://xtls.github.io/en/document/command.html#xray-vlessenc>
- TLS/SNI/fingerprint: <https://xtls.github.io/en/config/transports/tls.html>
- Apache RewriteRule `[P]`: <https://httpd.apache.org/docs/2.4/rewrite/flags.html#flag_p>
- ISPmanager API: <https://www.ispmanager.com/docs/ispmanager/ispmanager-api>
- Ограничения виртуального хостинга REG.RU:
  <https://help.reg.ru/support/hosting/zakaz-hostinga-rabota-s-uslugoy/sovety-po-vyboru-tarifa-hostinga>
- GitHub immutable releases:
  <https://docs.github.com/en/code-security/concepts/supply-chain-security/immutable-releases>
