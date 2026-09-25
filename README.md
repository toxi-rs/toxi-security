# toxi-security

Hashing, AES-GCM encryption, random tokens, and HTML sanitizing.

```toml
[dependencies]
toxi-security = "3"
```

```rust
use toxi_security::{encrypt, decrypt, sha256, sanitize_html};

let key = [0u8; 32];
let decrypted = decrypt(&key, &encrypt(&key, b"secret")?)?;
assert_eq!(decrypted, b"secret");
assert_eq!(sha256(b"hello").len(), 64);
assert!(!sanitize_html("<script>alert(1)</script>").contains("script"));
```
