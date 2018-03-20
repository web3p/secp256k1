<?php

namespace Test;

use \PHPUnit\Framework\TestCase as BaseTestCase;
use Web3p\Secp256k1\Serializer\HexSignatureSerializer;

class TestCase extends BaseTestCase
{
    /**
     * sigSerializer
     *
     * @var \Web3p\Secp256k1\Serializer\HexSignatureSerializer
     */
    protected $sigSerializer;

    /**
     * signed
     * 
     * @var string
     */
    protected $signed = 'f67118680df5993e8efca4d3ecc4172ca4ac5e3e007ea774293e37386480970347427f3633371c1a30abbb2b717dbd78ef63d5b19b5a951f9d681cccdd520320';

    /**
     * testPrivateKey
     * 
     * @var string
     */
    protected $testPrivateKey = 'd0459987fdde1f41e524fddbf4b646cd9d3bea7fd7d63feead3f5dfce6174a3d';

    /**
     * testPublicKey
     *
     * @var string
     */
    protected $testPublicKey = '04cf60398ae73fd947ffe120fba68947ec741fe696438d68a2e52caca139613ff94f220cd0d3e886f95aa226f2ad2b86be1dd5cda2813fd505d1f6a8f552904864';

    /**
     * setUp
     * 
     * @return void
     */
    public function setUp()
    {
        $this->sigSerializer = new HexSignatureSerializer();
    }

    /**
     * tearDown
     * 
     * @return void
     */
    public function tearDown() {}
}