# myrsa

Tool for file encryption using RSA algorithm without padding (aka “textbook RSA”).  
Note: This is an experimental tool for educational purposes.
Input is processed in chunks. The size of last chunk is appended to output in plaintext.

## Usage

Run with "--help"

```bash
myrsa --help
```
or
```bash
stack run -- --help
```
or
```bash
stack build
stack exec myrsa -- --help
```
