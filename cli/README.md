# dcap-qvl-cli

A CLI tool to decode TDX/SGX quote files.

## Usage

```
git clone https://github.com/Phala-Network/dcap-qvl.git
cd dcap-qvl/cli
cargo run -- decode-quote --hex ../sample/tdx-quote.hex | jq .
```

Strict verification:

```sh
cargo run -- verify --strict --hex ../sample/tdx-quote.hex
```
