XHTTP Setup @@VERSION@@ для Windows (через WSL2)

Требования: Windows 10/11, установленный WSL2 с Ubuntu/Debian, Python 3.10+, OpenSSH client и curl внутри WSL.

Запуск:
1. В Проводнике выберите для ZIP «Извлечь всё» и откройте полученную папку.
2. Запустите точный файл START-WINDOWS.cmd.
3. Введите запрошенные данные exit, frontend и необязательного bridge.

Установщик сам не устанавливает и не обновляет WSL. Если WSL ещё нет, выполните отдельно в PowerShell от администратора:
  wsl --install -d Ubuntu

Если в WSL нет нужных программ:
  sudo apt update
  sudo apt install python3 openssh-client curl

Пароли вводятся интерактивно внутри WSL. Они не записываются в файлы или аргументы команд.
Путь к SSH-ключу вводится как путь внутри выбранного WSL, например ~/.ssh/id_ed25519, а не C:\Users\...\.ssh\...
SSH fingerprints берите у провайдера независимо до запуска.
