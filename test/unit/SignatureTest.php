<?php

namespace Test\Unit;

use Test\TestCase;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\Curves\SecgCurve;
use Web3p\Secp256k1\Serializer\HexPrivateKeySerializer;
use Web3p\Secp256k1\Signature\Signer;
use Web3p\Secp256k1\Signature\Signature;

class SignatureTest extends TestCase
{
    /**
     * setUp
     *
     * @return void
     */
    // public function setUp()
    // {
    //     parent::setUp();
    // }

    /**
     * testToHex
     * 
     * @return void
     */
    public function testToHex()
    {
        $adapter = EccFactory::getAdapter();
        $generator = CurveFactory::getGeneratorByName(SecgCurve::NAME_SECP_256K1);
        $deserializer = new HexPrivateKeySerializer($generator);
        $key = $deserializer->parse($this->testPrivateKey);
        $hash = gmp_init('98d22cdb65bbf8a392180cd2ee892b0a971c47e7d29daf31a3286d006b9db4dc', 16);
        $random = \Mdanter\Ecc\Random\RandomGeneratorFactory::getHmacRandomGenerator($key, $hash, 'sha256');
        $n = $generator->getOrder();
        $randomK = $random->generate($n);

        $options = [
            'n' => $n,
            'canonical' => true
        ];
        $signer = new Signer($adapter, $options);
        $signature = $signer->sign($key, $hash, $randomK);

        $this->assertTrue($signature instanceof Signature);
        $this->assertEquals('f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e37386480970347427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320', $signature->toHex());
    }
}