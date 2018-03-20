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

use Mdanter\Ecc\Serializer\PrivateKey\PrivateKeySerializerInterface;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Primitives\Point;

class HexPrivateKeySerializer implements PrivateKeySerializerInterface
{
    /**
     * generator
     *
     * @var \Mdanter\Ecc\Primitives\Point
     */
    protected $generator;

    /**
     * construct
     *
     * @param \Mdanter\Ecc\Primitives\Point $generator
     * @return void
     */
    public function __construct(Point $generator)
    {
        $this->generator = $generator;
    }

    /**
     * serialize
     * 
     * @see \Mdanter\Ecc\Serializer\PrivateKey\PrivateKeySerializerInterface::serialize()
     * @param \Mdanter\Ecc\Crypto\Key\PrivateKeyInterface $key
     * @return string
     */
    public function serialize(PrivateKeyInterface $key): string
    {
        return gmp_strval($key->getSecret(), 16);
    }

    /**
     * parse
     * 
     * @see \Mdanter\Ecc\Serializer\PrivateKey\PrivateKeySerializerInterface::serialize()
     * @param string $formattedKey
     * @return \Mdanter\Ecc\Crypto\Key\PrivateKeyInterface
     */
    public function parse(string $formattedKey): PrivateKeyInterface
    {
        $key = gmp_init($formattedKey, 16);

        return $this->generator->getPrivateKeyFrom($key);
    }
}
