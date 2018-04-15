<?php
/**
 * This file is part of secp256k1 package.
 * 
 * (c) Kuan-Cheng,Lai <alk03073135@gmail.com>
 * 
 * @author Peter Lai <alk03073135@gmail.com>
 * @license MIT
 */

namespace Web3p\Secp256k1;

use InvalidArgumentException;
use RuntimeException;
use Mdanter\Ecc\EccFactory;
use Mdanter\Ecc\Curves\CurveFactory;
use Mdanter\Ecc\Curves\SecgCurve;
use Mdanter\Ecc\Crypto\Signature\SignatureInterface;
use Mdanter\Ecc\Random\RandomGeneratorFactory;
use Mdanter\Ecc\Primitives\PointInterface;
use Web3p\Secp256k1\Serializer\HexPrivateKeySerializer;
use Web3p\Secp256k1\Serializer\HexSignatureSerializer;
use Web3p\Secp256k1\Signature\Signer;

class Secp256k1
{
    /**
     * adapter
     *
     * @var \Mdanter\Ecc\Math\GmpMathInterface
     */
    protected $adapter;

    /**
     * generator
     *
     * @var \Mdanter\Ecc\Primitives\Point
     */
    protected $generator;

    /**
     * curve
     *
     * @var \Mdanter\Ecc\Curves\NamedCurveFp
     */
    protected $curve;

    /**
     * deserializer
     *
     * @var \Web3p\Secp256k1\Serializer\HexPrivateKeySerializer
     */
    protected $deserializer;

    /**
     * algorithm
     * 
     * @var string
     */
    protected $algorithm;

    /**
     * construct
     *
     * @param string $hashAlgorithm
     * @return void
     */
    public function __construct($hashAlgorithm='sha256')
    {
        $this->adapter = EccFactory::getAdapter();
        $this->generator = CurveFactory::getGeneratorByName(SecgCurve::NAME_SECP_256K1);
        $this->curve = $this->generator->getCurve();
        $this->deserializer = new HexPrivateKeySerializer($this->generator);
        $this->algorithm = $hashAlgorithm;
    }

    /**
     * get
     * 
     * @param string $name
     * @return mixed
     */
    public function __get($name)
    {
        $method = 'get' . ucfirst($name);

        if (method_exists($this, $method)) {
            return call_user_func_array([$this, $method], []);
        }
        return false;
    }

    /**
     * set
     * 
     * @param string $name
     * @param mixed $value
     * @return bool
     */
    public function __set($name, $value)
    {
        $method = 'set' . ucfirst($name);

        if (method_exists($this, $method)) {
            return call_user_func_array([$this, $method], [$value]);
        }
        return false;
    }

    /**
     * getDeserializer
     * 
     * @return \Web3p\Secp256k1\Serializer\HexPrivateKeySerializer
     */
    // public function getDeserializer()
    // {
    //     return $this->deserializer;
    // }

    /**
     * sign
     * 
     * @param string $hash
     * @param string $privateKey
     * @param array $options
     * @return \Mdanter\Ecc\Crypto\Signature\SignatureInterface
     */
    public function sign(string $hash, string $privateKey, array $options=[]): SignatureInterface
    {
        $key = $this->deserializer->parse($privateKey);
        $hash = gmp_init($hash, 16);

        if (!isset($options['n'])) {
            $random = RandomGeneratorFactory::getHmacRandomGenerator($key, $hash, $this->algorithm);
            $n = $this->generator->getOrder();
            $randomK = $random->generate($n);

            $options['n']  = $n;
        }
        if (!isset($options['canonical'])) {
            $options['canonical'] = true;
        }
        $signer = new Signer($this->adapter, $options);

        return $signer->sign($key, $hash, $randomK);
    }

    /**
     * verify
     * 
     * @param string $hash
     * @param \Mdanter\Ecc\Crypto\Signature\SignatureInterface $signature
     * @param string $publicKey
     * @return bool
     */
    public function verify(string $hash, SignatureInterface $signature, string $publicKey): bool
    {
        $gmpKey = $this->decodePoint($publicKey);
        $key = $this->generator->getPublickeyFrom($gmpKey->getX(), $gmpKey->getY());
        $hash = gmp_init($hash, 16);
        $signer = new Signer($this->adapter);

        return $signer->verify($key, $signature, $hash);
    }

    /**
     * decodePoint
     * 
     * @param string $publicKey
     * @return \Mdanter\Ecc\Primitives\PointInterface
     */
    protected function decodePoint(string $publicKey): PointInterface
    {
        $order = $this->generator->getOrder();
        $orderString = gmp_strval($order, 16);
        $length = mb_strlen($orderString);
        $keyLength = mb_strlen($publicKey);
        $num = hexdec(mb_substr($publicKey, 0, 2));

        if (
            ($num === 4 || $num === 6 || $num === 7) &&
            ($length * 2 + 2) === $keyLength
            ) {
            $x = gmp_init(mb_substr($publicKey, 2, $length), 16);
            $y = gmp_init(mb_substr($publicKey, ($length + 2), $length), 16);

            if ($this->generator->isValid($x, $y) !== true) {
                throw new InvalidArgumentException('Invalid public key point x and y.');
            }

            return $this->curve->getPoint($x, $y, $order);
        } elseif (
            ($num === 2 || $num === 3) &&
            ($length + 2) === $keyLength
        ) {
            $x = gmp_init(mb_substr($publicKey, 2, $length), 16);
            $y = $this->curve->recoverYfromX($num === 3, $x);

            return $this->curve->getPoint($x, $y, $order);
        }
        throw new InvalidArgumentException('Invalid public key point format.');
    }
}