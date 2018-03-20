# secp256k1
secp256k1 for ethereum, this package depends on mdanter/ecc package.

[![Build Status](https://travis-ci.org/web3p/secp256k1.svg?branch=master)](https://travis-ci.org/web3p/secp256k1)
[![codecov](https://codecov.io/gh/web3p/secp256k1/branch/master/graph/badge.svg)](https://codecov.io/gh/web3p/secp256k1)
[![Licensed under the MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/web3p/secp256k1/blob/master/LICENSE)

# Install

Set minimum stability to dev
```
composer require web3p/secp256k1
```

# Usage

Sign a message:
```php
use Web3p\Secp256k1\Secp256k1;
use Web3p\Secp256k1\Serializer\HexSignatureSerializer;

$secp256k1 = new Secp256k1();

// return signature contains r and s.
// message and privateKey are hex string
$signature = $secp256k1->sign($message, $privateKey);

// get r
$r = $signature->getR();

// get s
$s = $signature->getS();

// encode to hex
$serializer = new HexSignatureSerializer();
$signatureString = $serializer->serialize($signature);

// or you can call toHex
$signatureString = $signature->toHex();
```

Verify a message:
```php
use Web3p\Secp256k1\Secp256k1;

$secp256k1 = new Secp256k1();

// signature was created from sign method.
// hash and publicKey are hex string
$isVerified = $secp256k1->verify($hash, $signature, $publicKey);
```

# API

Todo.

# License
MIT

