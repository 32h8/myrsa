# myrsa

Tool for file encryption using RSA algorithm with OAEP padding. Written in Haskell. The hash function used is SHA256.  
Note: This is an experimental tool for educational purposes.

## Examples

Generate keys using default size and filenames
```bash
myrsa gen
```
Encrypt file
```bash
myrsa enc input.txt output
```

## Usage
sub-commands

```bash
$ myrsa --help
myrsa - an encryption CLI tool for educational purposes

Usage: <interactive> [--version] COMMAND

  Encrypts files using RSA algorithm (without padding).

Available options:
  -h,--help                Show this help text
  --version                Show version

Available commands:
  enc                      Encrypt a file
  dec                      Decrypt a file
  gen                      Generate keys

Note: This is an experimental tool
```

Generate keys
```bash
$ myrsa gen --help
Usage: <interactive> gen [-s|--key-size BITS] [--priv PRIVATE_KEY_FILE] 
                         [--pub PUBLIC_KEY_FILE] [-f]

  Generate keys

Available options:
  -s,--key-size BITS       Key size (modulus size in bits) (default: 2048)
  --priv PRIVATE_KEY_FILE  Private key file (default: "PRIV.txt")
  --pub PUBLIC_KEY_FILE    Public key file (default: "PUB.txt")
  -f                       Allow overwriting of existing key files
  -h,--help                Show this help text
```

Encrypt file
```bash
$ myrsa enc --help
Usage: <interactive> enc IN_FILE OUT_FILE [-k KEY_FILE]

  Encrypt a file

Available options:
  IN_FILE                  Input filename
  OUT_FILE                 Output filename
  -k KEY_FILE              Public key filename (default: "PUB.txt")
  -h,--help                Show this help text
```

Decrypt file
```bash
$ myrsa dec --help
Usage: <interactive> dec IN_FILE OUT_FILE [-k KEY_FILE] [--no-crt]

  Decrypt a file

Available options:
  IN_FILE                  Input filename
  OUT_FILE                 Output filename
  -k KEY_FILE              Private key filename (default: "PRIV.txt")
  --no-crt                 Do not use Chinese Remainder Theorem optimization
  -h,--help                Show this help text
```

## Run with Stack

```bash
stack run -- --help
```
or
```bash
stack build
stack exec myrsa -- --help
```

## License
BSD-3-Clause