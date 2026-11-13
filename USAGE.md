# Using Generated Keys with IPFS

## Quick Start

### 1. Generate a Vanity Key

```bash
ipfs-key -timeout=1m -suff=music,tests
# Output: keys/music_20260118_023938.key
# Output: keys/tests_20260118_023950.key
```

### 2. Import Key to IPFS

```bash
# Import the key
cat keys/music_20260118_023938.key | base64 | ipfs key import mykey

# Or directly:
ipfs key import mykey keys/music_20260118_023938.key
```

### 3. Verify the Key

```bash
ipfs key list -l
# Should show your key with the vanity suffix
```

## Common Use Cases

### Publishing IPNS with Vanity Address

```bash
# Generate key with custom suffix
ipfs-key -timeout=30s -suff=blog > mysite.key

# Import to IPFS
ipfs key import mysite mysite.key

# Publish content
ipfs name publish --key=mysite /ipfs/QmHash...

# Your content is now at: /ipns/12D3KooW...blog
```

### Multiple Keys for Different Projects

```bash
# Generate keys
ipfs-key -timeout=2m -suff=music,blog,docs

# Import all
ipfs key import music keys/music_*.key
ipfs key import blog keys/blog_*.key
ipfs key import docs keys/docs_*.key

# Use them
ipfs name publish --key=music /ipfs/QmMusicHash...
ipfs name publish --key=blog /ipfs/QmBlogHash...
ipfs name publish --key=docs /ipfs/QmDocsHash...
```

### Replace Default IPFS Node Identity

```bash
# Generate new identity (Ed25519 only)
ipfs-key -type=ed25519 > new-identity.key

# Note: Changing node identity requires manual config editing
# See IPFS documentation for details
```

## Key Management

### List All Generated Keys

```bash
ls -lh keys/
```

### Read Key Information

```bash
ipfs-key -key keys/music_20260118_023938.key
```

### Export Key from IPFS

```bash
ipfs key export mykey > exported.key
```

### Remove Key from IPFS

```bash
ipfs key rm mykey
```

## Security Notes

⚠️ **Important:**
- Keys are stored with `0600` permissions (owner read/write only)
- Never share your private keys
- Backup keys in a secure location
- Keys in `keys/` directory are your private keys - keep them safe!

## Advanced: Using with Kubo API

```bash
# Get key info
curl -X POST "http://127.0.0.1:5001/api/v0/key/list"

# Import key via API
curl -X POST -F file=@keys/music_*.key \
  "http://127.0.0.1:5001/api/v0/key/import?arg=mykey"

# Publish with key
curl -X POST \
  "http://127.0.0.1:5001/api/v0/name/publish?arg=/ipfs/QmHash&key=mykey"
```

## Troubleshooting

### Key Import Fails

```bash
# Check key format
ipfs-key -key keys/yourkey.key

# Try with base64 encoding
cat keys/yourkey.key | base64 | ipfs key import mykey
```

### Wrong Peer ID After Import

Make sure you're importing the raw key bytes, not base64 encoded.

### Permission Denied

```bash
chmod 600 keys/*.key
```

## Examples

### Personal Website with Vanity IPNS

```bash
# 1. Generate vanity key
ipfs-key -timeout=5m -suff=alice

# 2. Import to IPFS
ipfs key import alice-site keys/alice_*.key

# 3. Add your website
HASH=$(ipfs add -r website/ -Q)

# 4. Publish
ipfs name publish --key=alice-site /ipfs/$HASH

# 5. Your site is now at /ipns/12D3KooW...alice
```

### Music Collection

```bash
# Generate key
ipfs-key -timeout=2m -suff=tunes

# Import
ipfs key import my-music keys/tunes_*.key

# Add music
ipfs add -r music-collection/

# Publish
ipfs name publish --key=my-music /ipfs/QmMusicHash
```

## See Also

- [IPFS Key Management](https://docs.ipfs.tech/reference/kubo/cli/#ipfs-key)
- [IPNS Documentation](https://docs.ipfs.tech/concepts/ipns/)
- [Kubo API Reference](https://docs.ipfs.tech/reference/kubo/rpc/)
