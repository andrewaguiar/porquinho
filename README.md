# 🐷 porquinho

> *porquinho* — Portuguese for "little piggy bank". A safe place to drop your API keys.

**porquinho** is a small interactive CLI vault for API keys. It keeps them
AES-256-GCM encrypted in `~/.porquinho`, unlocked by a master key that only
you know and that is never written to disk.

## Why

API keys pile up in plaintext: `.env` files, dotfiles, shell history, random
`config.json`s. Credential scrapers — infostealer malware, malicious npm/PyPI
packages, poisoned build scripts — simply walk the filesystem grepping for
known paths and key patterns (`sk-...`, `AKIA...`) and exfiltrate everything
that matches. If an attacker can read your files, they have your secrets.

porquinho breaks that assumption: everything on disk is ciphertext. The
encryption key is derived from your master passphrase plus a random per-vault
salt and exists only in memory. Keys are entered via hidden prompts (nothing
in shell history), stay masked in `/list`, and are decrypted only when you
explicitly `/show` them. A scraper that steals the vault gets nothing usable.

## Usage

Run `porquinho`, enter your master key (a fresh vault registers it on first
use), and use the interactive prompt:

| Command   | Description                             |
|-----------|-----------------------------------------|
| `/list`   | List entries (keys stay hidden)         |
| `/create` | Create a new entry                      |
| `/update` | Change an entry's key                   |
| `/show`   | Show an entry with its key decrypted    |
| `/remove` | Remove an entry (asks for confirmation) |
| `/quit`   | Exit                                    |

## Building

```sh
cargo build --release
# or, to produce dist/porquinho for x86_64 Linux:
./scripts/build.sh
```

## Caveats

porquinho protects secrets *at rest* — not against keyloggers, memory readers,
or someone watching you `/show` a key. Pick a strong master key.
