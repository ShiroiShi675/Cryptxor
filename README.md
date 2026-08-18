# Cryptxor

Cryptxor is a command-line file encryption tool written in C. It has
two modes: XOR obfuscation for quick use cases, and authenticated AES-256-GCM encryption for real security, with keys derived from a password using Argon2id.

## Features

- XOR encryption/decryption (obfuscation, NOT cryptographically secure)
- AES-256-GCM encryption/decryption with authentication
- Password-based key derivation via Argon2id (libsodium), with a random salt for every file

## How It Works

XOR mode repeats the password as a byte stream and XORs it against the file contents. 
It's fast but offers no real security, it's meant only for casual obfuscation, or educational purposes.
AES-256 mode derives a 256-bit key from the password using Argon2id, then encrypts the file with AES-256-GCM. 
On encryption each encrypted file stores a random salt and IV before the ciphertext, followed by the authentication tag.
On decryption, the tag is verified before the output is considered valid, so any tampering or wrong password is detected rather than silently producing garbage data.

File Structure: `SALT|IV|CIPHERTEXT|TAG`

## Installing Dependencies

Cryptxor uses **libsodium** and **OpenSSL** libraries as dependencies.

**Linux (Debian/Ubuntu)**

```bash

sudo apt install libsodium-dev libssl-dev

```

**Linux (Fedora)**

```bash

sudo dnf install libsodium-devel openssl-devel

```

**macOS (Homebrew)**

```bash

brew install libsodium openssl

```

**Windows (MSYS2/MinGW)**

```bash

pacman -S mingw-w64-x86_64-libsodium mingw-w64-x86_64-openssl

```

## Build and Run

### Clone the repository:

```bash

git clone https://github.com/ShiroiShi675/Cryptxor.git

cd Cryptxor

```

### Linux / macOS

```bash

gcc main.c Cryptxor.c -o cryptxor -lsodium -lcrypto

./cryptxor

```

### Windows

```bash

gcc main.c Cryptxor.c -o cryptxor.exe -lsodium -lcrypto

cryptxor.exe

```

## Author

ShiroiShi
