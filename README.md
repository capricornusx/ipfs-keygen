# ipfs-keygen

> A high-performance tool for generating and reading IPFS keypairs with vanity address support

⚡ **Performance: ~540,000 keys/second** on 16-core CPU

## Table of Contents

- [Installation](#installation)
- [Usage](#usage)
  - [Fast Vanity Key Generation](#fast-vanity-key-generation)
  - [Standard Key Generation](#standard-key-generation)
  - [Reading Keys](#reading-keys)
  - [Using Keys with IPFS](#using-keys-with-ipfs)
- [Performance](#performance)
- [License](#license)

## Installation

```bash
# Build from source
make build
```

## Usage

### Fast Vanity Key Generation

Generate keys with custom suffixes at high speed:

```bash
ipfs-key -timeout=1m -suff=test,cool,music

# Output:
Config: Workers=16, Suffixes=[test cool music], Timeout=1m0s
Starting key generation...

[5s] 2680000 keys | 536000 keys/s
ID for generated key: 12D3KooWM71jqVWgASHvhKTcqi8q3HNyuLzYx81s5Vqtzteotest
PKey(base36): k51qzi5uqu5dkd2ayemr7z4naf7wedezvchgwi5o9fn9t43mryppe4bww3uuib

💾 Key saved: keys/test_20260118_023938.key

✓ Found!
```

**Options:**
- `-suff=test,cool` - Comma-separated list of suffixes (min 3 chars)
- `-timeout=1m` - Maximum search time (default: 10m)

**Key Storage:****
- Keys are automatically saved to `keys/` directory
- Filename format: `keys/{suffix}_{timestamp}.key`
- File permissions: 0600 (read/write for owner only)

**Performance:**
- 3 chars: ~0.1 seconds
- 4 chars: ~7 seconds
- 5 chars: ~3 minutes

### Reading Keys

Display information about existing keys:

```bash
ipfs-key -key my-key.key

# Output:
Reading key at: my-key.key
Success!
ID for ed25519 key: 12D3KooWF1TKgiqLMh14za7dWMN5RFRC1WAvgHYioksmdwuhZkzT
Private key (base64): CAESQLg...
```

### Using Keys with IPFS

Import generated keys into IPFS:

```bash
# Import key
ipfs key import mykey keys/music_20260118_023938.key

# Publish content with vanity address
ipfs name publish --key=mykey /ipfs/QmHash...

# Your content is now at: /ipns/12D3KooW...music
```

See [USAGE.md](USAGE.md) for detailed examples and advanced usage.

## Performance

This implementation is highly optimized for multi-core CPUs:

- **Throughput**: ~540,000 keys/second (16 cores)
- **Efficiency**: Zero allocations in hot path
- **Scaling**: Linear scaling across CPU cores
- **Memory**: Minimal GC pressure

See [PERFORMANCE_COMPARISON.md](PERFORMANCE_COMPARISON.md) for detailed benchmarks.

### Calculate Probability

Estimate time to find a vanity suffix:

```bash
make probability SUFF=test,cool,music
```

## License

[MIT](LICENSE) Copyright (c) 2016 [Jeromy Johnson](http://github.com/whyrusleeping)
