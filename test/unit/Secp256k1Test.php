<?php

namespace Test\Unit;

use Test\TestCase;
use Secp256k1\Serializer\HexPrivateKeySerializer;
use Secp256k1\Secp256k1;

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