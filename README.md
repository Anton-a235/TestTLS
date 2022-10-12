# TestTLS
Клиент-серверное оконное приложение для тестирования скорости обмена сообщениями по протоколу TLS 1.3 с использованием OpenSSL 3.0

Для генерации сертификатов поддерживаются алгоритмы подписи
- RSA (3072 бита)
- ECDSA (secp256r1)
- Ed25519

Приложение реализует интерфейс, с помощью которого со стороны сервера можно выбрать алгоритм согласования на данную сессию, а со стороны клиента указать адрес сервера, который будет принимать соединение.

В режиме тестирования скорости приложение выводит сводную таблицу, в которой отображено: 
- скорость создания подписи;
- скорость верификации подписи;
- скорость установки хендшейка;
- время полного обмена данными.

Установка соединения и обмен сообщениями производится некоторое количество раз подряд, а результат отображается в таблице с указанием минимального, среднего, максимального значений, а также медианы и 90 и 99 перцентилей.

Предусмотрено логирование ключа шифрования сессии в файл в формате NSS Key Log Format, с возможностью его использования для просмотра дешифрованного трафика в Wireshark.

![image](https://user-images.githubusercontent.com/88583217/194897838-6607c6ab-03dd-4385-80d0-654c905f70f6.png)

![image](https://user-images.githubusercontent.com/88583217/194898098-717640f6-c78a-43e8-a2db-6f67624a3fcf.png)
