# ipfs-keygen

Генератор IPFS/IPNS-ключей Ed25519 с поиском ключей, чьи PeerID или IPNS-имена оканчиваются на заданные суффиксы. Полезен для получения запоминающихся IPNS-адресов или выделенных ключей для нод и релизов. В отличие от ручного перебора, использует все доступные ядра CPU и сразу сохраняет найденные ключи в файлы.

- **Vanity-суффиксы.** Ищет совпадения в PeerID и/или IPNS base36 по списку через запятую.
- **Режимы поиска.** `all` (по умолчанию), `peerid` или `ipns`.
- **Многопоточность.** Количество воркеров равно `runtime.NumCPU()`.
- **Сохранение.** Ключи пишутся в `keys/<kind>/<suffix>_<timestamp>.key` с правами `0600`.
- **Чтение ключей.** `ipfs-key -key <path>` показывает PeerID, IPNS base36 и base64 приватного ключа.
- **Минимальная длина суффикса.** 4 символа.

## Пример

```bash
make build

dist/ipfs-key -timeout=1m -mode=ipns -suff=music
# Config: Workers=16, Suffixes=[music], Timeout=1m0s, Mode=ipns
# Starting key generation...
#
# [10s] N keys | R keys/s | 1/1 suffixes remaining
#
# ID for generated key: 12D3KooWM71jqVWgASHvhKTcqi8q3HNyuLzYx81s5Vqtzteomusic
# PKey(base36): k51qzi5uqu5dkd2ayemr7z4naf7wedezvchgwi5o9fn9t43mryppe4bww3uuib
# Matched: ipns
# Key saved: keys/ipns/music_20260810_123045.key
#
# Total: N keys in T s (R keys/s)
# Found 1/1 keys!
#   - music (ipns)
```

## Быстрый старт

```bash
# 1. Сборка
make build                 # -> dist/ipfs-key

# 2. Сгенерировать ключ с нужным суффиксом
dist/ipfs-key -timeout=5m -mode=ipns -suff=music,blog

# 3. Импортировать в Kubo
ipfs key import mysite keys/ipns/music_*.key

# 4. Опубликовать контент через IPNS
ipfs name publish --key=mysite /ipfs/QmHash...
# Контент доступен по адресу /ipns/<peerid>...music
```

## Готовый набор суффиксов

В Makefile есть цель `run`, которая запускает генерацию фиксированного набора суффиксов:

```bash
make run
# эквивалентно:
# ./dist/ipfs-key -timeout=10m -mode=ipns \
#   -suff=kubo,bench,release,latest,swarmagent,bbuild,abuild,petabyte,science
```

## Использование существующего ключа

```bash
dist/ipfs-key -key keys/ipns/music_20260810_123045.key
# ID for ed25519 key: 12D3KooW...music
# ID (base36/IPNS): k51qzi5uqu5...
# Private key (base64): CAESQLg...
```

## Разработка

В репозитории действует единый Makefile-контракт:

```bash
make lint    # golangci-lint, read-only
make test    # go test -count=1 -short
make build   # бинарь в dist/
make help    # все цели репо
```

Git hooks:

```bash
lefthook install
```

Подробные сценарии использования, импорт через Kubo API и безопасность ключей описаны в [USAGE.md](USAGE.md).

## License

[MIT](LICENSE) Copyright (c) 2016 [Jeromy Johnson](http://github.com/whyrusleeping)
