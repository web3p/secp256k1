<?php

namespace Test\Unit;

use Test\TestCase;
use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\Curves\SecgCurve;
use Web3p\Secp256k1\Serializer\HexPrivateKeySerializer;

class HexPrivateKeySerializerTest extends TestCase
{
    /**
     * serializer
     *
     * @var \Secp256k1\Serializer\HexPrivateKeySerializer
     */
    protected $serializer;

    /**
     * setUp
     *
     * @return void
     */
    public function setUp()
    {
        parent::setUp();
        $generator = CurveFactory::getGeneratorByName(SecgCurve::NAME_SECP_256K1);

        $this->serializer = new HexPrivateKeySerializer($generator);
    }

    /**
     * testParse
     * 
     * @return void
     */
    public function testParse()
    {
        $key = $this->serializer->parse($this->testPrivateKey);
        $this->assertEquals(gmp_init($this->testPrivateKey, 16), $key->getSecret());

        $key = $this->serializer->parse('0x' . $this->testPrivateKey);
        $this->assertEquals(gmp_init($this->testPrivateKey, 16), $key->getSecret());
    }

    /**
     * testSerialize
     * 
     * @return void
     */
    public function testSerialize()
    {
        $key = $this->serializer->serialize($this->serializer->parse($this->testPrivateKey));
        $this->assertEquals($this->testPrivateKey, $key);

        $key = $this->serializer->serialize($this->serializer->parse('0x' . $this->testPrivateKey));
        $this->assertEquals($this->testPrivateKey, $key);
    }
}