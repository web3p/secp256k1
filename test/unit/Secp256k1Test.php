<?php

namespace Test\Unit;

use Test\TestCase;
use Web3p\Secp256k1\Serializer\HexPrivateKeySerializer;
use Web3p\Secp256k1\Secp256k1;

class Secp256k1Test extends TestCase
{
    /**
     * secp256k1
     *
     * @var \Secp256k1\Secp256k1
     */
    protected $secp256k1;

    /**
     * setUp
     *
     * @return void
     */
    public function setUp()
    {
        parent::setUp();
        $this->secp256k1 = new Secp256k1();
    }

    /**
     * testGetDeserializer
     * 
     * @return void
     */
    // public function testGetDeserializer()
    // {
    //     $this->assertTrue($this->secp256k1->deserializer instanceof HexPrivateKeySerializer);
    // }

    /**
     * testSign
     * 
     * @return void
     */
    public function testSign()
    {
        $signature = $this->secp256k1->sign('98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc', $this->testPrivateKey);

        $this->assertEquals('f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e373864809703', gmp_strval($signature->getR(), 16));
        $this->assertEquals('47427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320', gmp_strval($signature->getS(), 16));
        $this->assertEquals(0, $signature->getRecoveryParam());

        $signature = $this->secp256k1->sign('710aee292b0f1749aaa0cfef67111e2f716afbdb475e7f250bdb80c6655b0a66', $this->testPrivateKey);

        $this->assertEquals('8d8bfd01c48454b5b3fed2361cbd0e8c3282d5bd2e26762e4c9dfbe1ef35f325', gmp_strval($signature->getR(), 16));
        $this->assertEquals('6d6a5dc397934b5544835f34ff24263cbc00bdd516b6f0df3f29cdf6c779ccfb', gmp_strval($signature->getS(), 16));
        $this->assertEquals(0, $signature->getRecoveryParam());
    }

    /**
     * testVerify
     * 
     * @return void
     */
    public function testVerify()
    {
        $signature = $this->secp256k1->sign('98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc', $this->testPrivateKey);

        $this->assertTrue($this->secp256k1->verify('98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc', $signature, $this->testPublicKey));
    }
}