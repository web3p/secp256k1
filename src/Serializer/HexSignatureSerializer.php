<?php
/**
 * This file is part of secp256k1 package.
 * 
 * (c) Kuan-Cheng,Lai <alk03073135@gmail.com>
 * 
 * @author Peter Lai <alk03073135@gmail.com>
 * @license MIT
 */

namespace Web3p\Secp256k1\Serializer;

use InvalidArgumentException;
use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\Crypto\Signature\SignatureInterface;

class HexSignatureSerializer
{
    /**
     * serialize
     * 
     * @param \Mdanter\Ecc\Crypto\Signature\SignatureInterface $signature
     * @return string
     */
    public function serialize(SignatureInterface $signature): string
    {
        $r = $signature->getR();
        $s = $signature->getS();

        return gmp_strval($r, 16) . gmp_strval($s, 16);
    }

    /**
     * parse
     * 
     * @param string $binary
     * @return \Mdanter\Ecc\Crypto\Signature\SignatureInterface
     */
    public function parse(string $binary): SignatureInterface
    {
        $binary = mb_strtolower($binary);

        if (strpos($binary, '0x') >= 0) {
            $count = 1;
            $binary = str_replace('0x', '', $binary, $count);
        }
        if (mb_strlen($binary) !== 128) {
            throw new InvalidArgumentException('Binary string was not correct.');
        }
        $r = mb_substr($binary, 0, 64);
        $s = mb_substr($binary, 64, 64);

        return new Signature(
            gmp_init($r, 16),
            gmp_init($s, 16)
        );
    }
}
