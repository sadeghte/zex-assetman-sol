# Zellular Exchange Asset Manager for the Solana Network

## Run test validator
```bash
$ solana-test-validator
$ solana airdrop 100
```

## Setup test environment
```bash
# config solana to use localnet
$ solana config set --url http://127.0.0.1:8899
# default path: ~/.config/solana/id.json
$ solana-keygen new --outfile /path/to/your-wallet.json
```
Clone the `.env.example` file, rename it to `.env`, then set the `ANCHOR_WALLET` value's with your wallet path.

## build and deploy
```bash
$ anchor build
$ anchor deploy
```

## Run test file
```bash
npx ts-node tests/assetman.test.ts
```