<?php

namespace Test\Unit;

use Test\TestCase;
use Secp256k1\Serializer\HexSignatureSerializer;

class HexSignatureSerializerTest extends TestCase
{
    /**
     * serializer
     *
     * @var \Secp256k1\Serializer\HexSignatureSerializer
     */
    protected $serializer;

    /**
     * signed
     * 
     * @var string
     */
    protected $signed = 'f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e37386480970347427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320';

    /**
     * setUp
     *
     * @return void
     */
    public function setUp()
    {
        parent::setUp();
        $this->serializer = new HexSignatureSerializer();
    }

    /**
     * testParse
     * 
     * @return void
     */
    public function testParse()
    {
        $sig = $this->serializer->parse($this->signed);
        $r = $sig->getR();
        $s = $sig->getS();
        $this->assertEquals($this->signed, gmp_strval($r, 16) . gmp_strval($s, 16));

        $sig = $this->serializer->parse('0x' . $this->signed);
        $r = $sig->getR();
        $s = $sig->getS();
        $this->assertEquals($this->signed, gmp_strval($r, 16) . gmp_strval($s, 16));
    }

    /**
     * testSerialize
     * 
     * @return void
     */
    public function testSerialize()
    {
        $sig = $this->serializer->parse($this->signed);
        $signed = $this->serializer->serialize($sig);
        $this->assertEquals($this->signed, $signed);

        $sig = $this->serializer->parse('0x' . $this->signed);
        $signed = $this->serializer->serialize($sig);
        $this->assertEquals($this->signed, $signed);
    }
}