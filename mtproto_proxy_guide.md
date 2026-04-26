# Как работает MTProto прокси в Telegram Desktop

## Обзор архитектуры

MTProto прокси в Telegram Desktop — это специальный тип прокси-сервера, разработанный командой Telegram для обхода блокировок. В отличие от стандартных SOCKS5 или HTTP прокси, MTProto прокси использует тот же протокол, что и основное соединение с серверами Telegram, что делает его трафик менее заметным для систем фильтрации.

## 1. Структура данных прокси

### MTP::ProxyData (mtproto_proxy_data.h)

Основная структура данных для хранения информации о прокси:

```cpp
struct ProxyData {
    enum class Type {
        None,      // Без прокси
        Socks5,    // SOCKS5 прокси
        Http,      // HTTP прокси
        Mtproto,   // MTProto прокси
    };
    
    enum class Settings {
        System,    // Использовать системные настройки
        Enabled,   // Прокси включен
        Disabled,  // Прокси отключен
    };
    
    enum class Status {
        Valid,           // Валидный прокси
        Unsupported,     // Неподдерживаемый тип
        IncorrectSecret, // Неверный секрет
        Invalid,         // Некорректные данные
    };
    
    Type type = Type::None;
    QString host;
    uint32 port = 0;
    QString user, password;  // Для MTProto - это secret
    
    std::vector<QString> resolvedIPs;  // Кэшированные IP-адреса
    crl::time resolvedExpireAt = 0;    // Время истечения кэша
};
```

### Формат секрета для MTProto прокси

Секрет может быть в двух форматах:

1. **Hex формат**: 32+ hex символа (16+ байт)
   - Пример: `ee1234567890abcdef1234567890abcdef`
   
2. **Base64URL формат**: 22+ символа Base64URL
   - Пример: `7gEBAAAA...` (без паддинга `=`)

Проверка валидности (`mtproto_proxy_data.cpp`):
- 16 байт (128 бит) - базовый формат
- 17 байт с префиксом `0xDD` - DD-режим (obfuscation)
- 21+ байт с префиксом `0xEE` - EE-режим (TLS obfuscation)

## 2. Настройки прокси

### Core::SettingsProxy (core_settings_proxy.h/cpp)

Класс управляет всеми настройками прокси:

```cpp
class SettingsProxy {
    bool _tryIPv6 = false;                    // Пробовать IPv6
    bool _useProxyForCalls = false;           // Использовать для звонков
    bool _proxyRotationEnabled = false;       // Авто-переключение
    int _proxyRotationTimeout = 10;           // Таймаут ротации (сек)
    MTP::ProxyData::Settings _settings;       // Режим работы
    MTP::ProxyData _selected;                 // Текущий прокси
    std::vector<MTP::ProxyData> _list;        // Список всех прокси
    std::vector<int> _proxyRotationPreferredIndices;  // Приоритеты
};
```

**Сериализация настроек:**
Настройки сохраняются в бинарном формате через `serialize()` / `setFromSerialized()`.

## 3. Подключение к MTProto прокси

### 3.1 Инициализация соединения

Файл: `mtproto/connection_tcp.cpp`

```cpp
void TcpConnection::connectToServer(
        const QString &address,
        int port,
        const bytes::vector &protocolSecret,
        int16 protocolDcId,
        bool protocolForFiles) {
    
    // Для MTProto прокси используем хост/порт прокси
    const auto secret = (_proxy.type == ProxyData::Type::Mtproto)
        ? _proxy.secretFromMtprotoPassword()  // Декодируем секрет
        : protocolSecret;
    
    if (_proxy.type == ProxyData::Type::Mtproto) {
        _address = _proxy.host;
        _port = _proxy.port;
        _protocol = Protocol::Create(secret);
    } else {
        _address = address;
        _port = port;
        _protocol = Protocol::Create(secret);
    }
    
    // Создаем сокет с настройками прокси
    _socket = AbstractSocket::Create(
        thread(),
        secret,
        ToNetworkProxy(_proxy),
        protocolForFiles);
    
    _socket->connectToHost(_address, _port);
}
```

### 3.2 Создание сокета

Файл: `mtproto/details/mtproto_abstract_socket.cpp`

```cpp
std::unique_ptr<AbstractSocket> AbstractSocket::Create(
        not_null<QThread*> thread,
        const bytes::vector &secret,
        const QNetworkProxy &proxy,
        bool protocolForFiles) {
    
    // Если секрет начинается с 0xEE - используем TLS обфускацию
    if (secret.size() >= 21 && secret[0] == bytes::type(0xEE)) {
        return std::make_unique<TlsSocket>(thread, secret, proxy, protocolForFiles);
    } else {
        // Обычный TCP сокет
        return std::make_unique<TcpSocket>(thread, proxy, protocolForFiles);
    }
}
```

### 3.3 Настройка QTcpSocket

Файл: `mtproto/details/mtproto_tcp_socket.cpp`

```cpp
TcpSocket::TcpSocket(
        not_null<QThread*> thread,
        const QNetworkProxy &proxy,
        bool protocolForFiles)
    : AbstractSocket(thread) {
    
    _socket.moveToThread(thread);
    _socket.setProxy(proxy);  // Устанавливаем QNetworkProxy
    
    // Настраиваем буферы для файловых операций
    if (protocolForFiles) {
        _socket.setSocketOption(QAbstractSocket::SendBufferSizeSocketOption, 
                                kFilesSendBufferSize);
        _socket.setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption, 
                                kFilesReceiveBufferSize);
    }
    
    // Подключаем сигналы Qt
    connect(&_socket, &QTcpSocket::connected, ...);
    connect(&_socket, &QTcpSocket::disconnected, ...);
    connect(&_socket, &QTcpSocket::readyRead, ...);
    connect(&_socket, &QAbstractSocket::errorOccurred, ...);
}
```

## 4. Протоколы MTProto соединения

### 4.1 Типы протоколов (connection_tcp.cpp)

```cpp
class TcpConnection::Protocol {
    // Version0 - без обфускации
    class Version0 : public Protocol {
        uint32 id() const override { return 0xEFEFEFEFU; }
    };
    
    // Version1 - с обфускацией (секрет 16 байт)
    class Version1 : public Version0 {
        void prepareKey(bytes::span key, bytes::const_span source) override {
            const auto payload = bytes::concatenate(source, _secret);
            bytes::copy(key, openssl::Sha256(payload));  // SHA256 для ключа
        }
    };
    
    // VersionD - DD-режим (секрет 17 байт, префикс 0xDD)
    class VersionD : public Version1 {
        uint32 id() const override { return 0xDDDDDDDDU; }
        bool supportsArbitraryLength() const override { return true; }
    };
};
```

### 4.2 Создание протокола

```cpp
auto TcpConnection::Protocol::Create(bytes::const_span secret) 
    -> std::unique_ptr<Protocol> {
    
    if ((secret.size() >= 21 && secret[0] == bytes::type(0xEE))
        || (secret.size() == 17 && secret[0] == bytes::type(0xDD))) {
        // DD или EE режим
        return std::make_unique<VersionD>(
            bytes::make_vector(secret.subspan(1, 16)));
    } else if (secret.size() == 16) {
        // Обычная обфускация
        return std::make_unique<Version1>(bytes::make_vector(secret));
    } else if (secret.empty()) {
        // Без обфускации
        return std::make_unique<Version0>();
    }
}
```

## 5. Процесс установления соединения

### 5.1 Подготовка префикса соединения

Файл: `mtproto/connection_tcp.cpp`

```cpp
bytes::const_span TcpConnection::prepareConnectionStartPrefix(
        bytes::span buffer) {
    
    if (_connectionStarted) {
        return {};
    }
    _connectionStarted = true;
    
    // Генерируем случайный nonce (64 байта)
    char nonceBytes[64];
    const auto nonce = bytes::make_span(nonceBytes);
    do {
        bytes::set_random(nonce);
    } while (!_socket->isGoodStartNonce(nonce));  // Проверка на зарезервированные значения
    
    // Создаем ключи шифрования из nonce
    _protocol->prepareKey(
        bytes::make_span(_sendKey),
        nonce.subspan(8, CTRState::KeySize));  // 32 байта для AES ключа
    
    bytes::copy(
        bytes::make_span(_sendState.ivec),
        nonce.subspan(8 + CTRState::KeySize, CTRState::IvecSize));  // 16 байт для IV
    
    // Для decryption - реверсивный ключ
    auto reversedBytes = bytes::vector(48);
    bytes::copy(reversed, nonce.subspan(8, reversed.size()));
    std::reverse(reversed.begin(), reversed.end());
    _protocol->prepareKey(
        bytes::make_span(_receiveKey),
        reversed.subspan(0, CTRState::KeySize));
    
    // Записываем ID протокола и DC ID
    const auto protocol = reinterpret_cast<uint32*>(nonce.data() + 56);
    *protocol = _protocol->id();  // 0xEFEFEFEF, 0xDDDDDDDD и т.д.
    const auto dcId = reinterpret_cast<int16*>(nonce.data() + 60);
    *dcId = _protocolDcId;
    
    // Шифруем nonce
    bytes::copy(buffer, nonce.subspan(0, 56));
    aesCtrEncrypt(nonce, _sendKey, &_sendState);
    bytes::copy(buffer.subspan(56), nonce.subspan(56));
    
    return buffer;  // 64 байта префикса
}
```

### 5.2 Отправка данных

```cpp
void TcpConnection::sendData(mtpBuffer &&buffer) {
    // Подготовка 64-байтного префикса
    char connectionStartPrefixBytes[kConnectionStartPrefixSize];
    const auto connectionStartPrefix = prepareConnectionStartPrefix(
        bytes::make_span(connectionStartPrefixBytes));
    
    // Форматирование пакета согласно протоколу
    const auto bytes = _protocol->finalizePacket(buffer);
    
    // Шифрование пакета AES-CTR
    aesCtrEncrypt(bytes, _sendKey, &_sendState);
    
    // Отправка префикса и данных
    _socket->write(connectionStartPrefix, bytes);
}
```

### 5.3 Чтение данных

```cpp
void TcpConnection::socketRead() {
    do {
        // Чтение сырых данных из сокета
        const auto readCount = _socket->read(free.subspan(0, readLimit));
        
        if (readCount > 0) {
            // Расшифровка AES-CTR
            const auto read = free.subspan(0, readCount);
            aesCtrEncrypt(read, _receiveKey, &_receiveState);
            
            // Парсинг пакетов
            while (_readBytes > 0) {
                const auto packetSize = _protocol->readPacketLength(available);
                
                if (packetSize > 0 && available.size() >= packetSize) {
                    socketPacket(available.subspan(0, packetSize));
                    // Обработка пакета...
                }
            }
        }
    } while (_socket && _socket->isConnected() && _socket->hasBytesAvailable());
}
```

## 6. Проверка работоспособности прокси

### 6.1 StartProxyCheck (proxy_check.cpp)

```cpp
void StartProxyCheck(
        not_null<Instance*> mtproto,
        const ProxyData &proxy,
        bool tryIPv6,
        ProxyCheckConnection &v4,
        ProxyCheckConnection &v6,
        Fn<void(Connection *raw, int ping)> done,
        Fn<void(Connection *raw)> fail) {
    
    if (proxy.type == ProxyData::Type::Mtproto) {
        const auto secret = proxy.secretFromMtprotoPassword();
        
        // Создаем соединение для проверки
        setup(v4, secret);
        
        // Подключаемся напрямую к прокси
        v4->connectToServer(
            proxy.host,
            proxy.port,
            secret,
            dcId,
            false);
        return;
    }
    
    // Для других типов прокси - проверка через сервера Telegram
    // ...
}
```

## 7. Ротация прокси

### 7.1 ProxyRotationManager (proxy_rotation_manager.h/cpp)

Автоматическое переключение между прокси при проблемах с соединением:

```cpp
class ProxyRotationManager {
    struct Entry {
        MTP::ProxyData proxy;
        MTP::ProxyCheckConnection v4;  // Проверка IPv4
        MTP::ProxyCheckConnection v6;  // Проверка IPv6
        bool checking = false;
        crl::time startedAt = 0;
        crl::time availableAt = 0;
    };
    
    void runChecks() {
        // Периодическая проверка всех прокси в списке
        pruneExpiredChecks();
        startNextCheck();
        continueChecking(kProxyRotationCheckInterval);  // 2 секунды
    }
    
    void startNextCheck() {
        // Проверка следующего прокси в порядке приоритета
        const auto &proxy = settings.list()[listIndex];
        auto &entry = ensure(proxy);
        
        MTP::StartProxyCheck(
            &accountForChecks()->mtp(),
            proxy,
            settings.tryIPv6(),
            entry.v4,
            entry.v6,
            [=](auto *raw, int ping) { checkDone(proxy, raw, ping); },
            [=](auto *raw) { checkFailed(proxy, raw); });
    }
    
    bool switchToAvailable() {
        // Переключение на первый доступный прокси
        for (const auto index : _probeOrder) {
            const auto &proxy = settings.list()[index];
            const auto entry = find(proxy);
            
            if (entry && !entry->checking && entry->availableAt) {
                App().setCurrentProxy(proxy, MTP::ProxyData::Settings::Enabled);
                return true;
            }
        }
        return false;
    }
};
```

## 8. Добавление прокси через ссылку

### 8.1 Обработка tg://proxy ссылок

Файл: `core/local_url_handlers.cpp`

```cpp
bool ApplyMtprotoProxy(
        Window::SessionController *controller,
        const Match &match,
        const QVariant &context) {
    
    // Парсинг параметров из URL
    auto params = url_parse_params(
        match->captured(1),
        qthelp::UrlParamNameTransform::ToLower);
    
    // Нормализация секрета (+ -> -, / -> _)
    auto &secret = params[u"secret"_q];
    secret.replace('+', '-').replace('/', '_');
    
    // Показ диалога подтверждения
    ProxiesBoxController::ShowApplyConfirmation(
        controller,
        MTP::ProxyData::Type::Mtproto,
        params);
}
```

### 8.2 Формат ссылки

```
tg://proxy?server=<host>&port=<port>&secret=<secret>

Пример:
tg://proxy?server=proxy.example.com&port=443&secret=ee1234567890abcdef1234567890abcdef
```

Также поддерживаются HTTPS ссылки:
```
https://t.me/proxy?server=...&port=...&secret=...
```

### 8.3 Преобразование в QR-код

Файл: `boxes/connection_box.cpp`

```cpp
QString ProxyDataToQueryPath(const ProxyData &proxy) {
    return u"proxy"_q
        + "?server=" + proxy.host 
        + "&port=" + QString::number(proxy.port)
        + "&secret=" + proxy.password;  // secret в MTProto
}

QString ProxyDataToLocalLink(const ProxyData &proxy) {
    return u"tg://"_q + ProxyDataToQueryPath(proxy);
}
```

## 9. Полная схема подключения

```
┌─────────────────────────────────────────────────────────────────┐
│                    Telegram Desktop                              │
│                                                                  │
│  ┌──────────────┐                                               │
│  │  UI Layer    │ ← Пользователь добавляет прокси               │
│  │  (connection │   через настройки или tg:// ссылку            │
│  │   _box.cpp)  │                                               │
│  └──────┬───────┘                                               │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────┐                                               │
│  │  Settings    │ ← Сохранение в Core::SettingsProxy            │
│  │  Proxy       │   - список прокси                             │
│  │  (core_sett  │   - текущий выбранный                         │
│  │   ings_prox  │   - настройки ротации                         │
│  │   y.cpp)     │                                               │
│  └──────┬───────┘                                               │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────┐                                               │
│  │  MTP::Instanc│ ← Основной экземпляр MTProto                  │
│  │  e           │                                               │
│  └──────┬───────┘                                               │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────┐                                               │
│  │  Connection  │ ← TcpConnection создает соединение            │
│  │  TCP         │   с прокси                                    │
│  │  (connectio  │                                               │
│  │  n_tcp.cpp)  │                                               │
│  └──────┬───────┘                                               │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────┐                                               │
│  │  Abstract    │ ← Выбор TcpSocket или TlsSocket              │
│  │  Socket      │   в зависимости от типа секрета               │
│  │  (mtproto_ab │                                               │
│  │  stract_soc  │                                               │
│  │  ket.cpp)    │                                               │
│  └──────┬───────┘                                               │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────┐                                               │
│  │  TcpSocket   │ ← QTcpSocket с установленным QNetworkProxy   │
│  │  (mtproto_tc │                                               │
│  │  p_socket.cp │                                               │
│  │  p)          │                                               │
│  └──────┬───────┘                                               │
│         │                                                        │
│         ▼                                                        │
│  ┌──────────────┐                                               │
│  │  MTProto     │ ← 64-байтный префикс + зашифрованные пакеты  │
│  │  Protocol    │   AES-CTR шифрование                          │
│  │  (Version0/  │   Protocol ID: 0xEFEFEFEF / 0xDDDDDDDD       │
│  │   1/D)       │                                               │
│  └──────┬───────┘                                               │
│         │                                                        │
└──────────┼───────────────────────────────────────────────────────┘
           │
           ▼
    ┌──────────────┐
    │ MTProto Proxy│ ← Принимает соединение на порту 443/8443 etc
    │ Server       │   Проверяет секрет (16/17/21+ байт)         │
    │              │   Перенаправляет трафик на сервер Telegram  │
    └──────┬───────┘
           │
           ▼
    ┌──────────────┐
    │ Telegram DC  │ ← Дата-центр Telegram
    └──────────────┘
```

## 10. Ключевые особенности MTProto прокси

1. **Обфускация трафика**: Использует тот же протокол, что и прямое соединение с Telegram
2. **Гибкие типы секретов**: Поддержка разных режимов (plain, DD, EE)
3. **AES-CTR шифрование**: Все пакеты шифруются потоковым шифром
4. **Авто-ротация**: Автоматическое переключение между прокси при сбоях
5. **Проверка доступности**: Фоновая проверка всех прокси в списке
6. **Deep linking**: Поддержка ссылок формата `tg://proxy?...`
7. **QR-коды**: Генерация QR для быстрого добавления прокси

## 11. Отличия от обычных прокси

| Характеристика | SOCKS5/HTTP | MTProto Proxy |
|---------------|-------------|---------------|
| Протокол | Стандартный RFC | Проприетарный MTProto |
| Обфускация | Нет | Да (TLS-like) |
| Секрет | Логин/пароль | 16-32 байт hex/base64 |
| Порт | Любой | Обычно 443 (как HTTPS) |
| Распознавание | Легко | Сложно (как Telegram трафик) |
| Поддержка звонков | Ограничена | Нет (только сообщения) |

## Заключение

MTProto прокси в Telegram Desktop представляет собой сложную систему с многоуровневой архитектурой, обеспечивающей надежное и безопасное соединение через прокси-серверы. Ключевыми компонентами являются:

- **Core::SettingsProxy** - управление настройками
- **MTP::ProxyData** - структура данных прокси
- **TcpConnection** - установление соединения
- **AbstractSocket/TcpSocket** - низкоуровневое сетевое взаимодействие
- **Protocol (Version0/1/D)** - реализация различных режимов протокола
- **ProxyRotationManager** - автоматическая ротация и проверка

Эта архитектура позволяет Telegram Desktop эффективно работать в условиях интернет-цензуры, предоставляя пользователям надежный инструмент для обхода блокировок.
