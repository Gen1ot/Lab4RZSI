# Lab4RZSI
Предложена консольная реализация шифратора папок на языке С++. Для шифрования использрована библиотека Crypto++ Library.
В файле Sercher реализован рекурсивный обход папок с целью шифрования всех вложенных файлов.

# Инструкция для установки
Необходимо для запуска этого проекта установить Crypto++ Library
```
sudo apt update
sudo apt install libcrypto++-dev libcrypto++-utils libcrypto++-doc
```
Также может понадобиться дополнительная установка утилиты для CMake
```
sudo apt update
sudo apt install pkg-config
```
После установки всего необходимого можно перейти к сборке и запуску проекта.

# Инструкция по сборке и запуску
## Сборка
```
mkdir build && cd build
cmake ..
make
```
## Запуск
```
./main
```

После запуска появится предложение выбора дальнейших действий
```
1. Encrypt folder
2. Decrypt folder
What do you choose?
```

После ввода цисла, соответсвующего Вашему выбору повяится просьба ввести путь до папке, которую хотите зашифровать, и пароль, необходимый для шифрования
```
Enter the path: (например такой:/mnt/c/rszi)
Give me your password, pls: mypass
```
