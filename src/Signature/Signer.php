<?php
/**
 * This file is part of secp256k1 package.
 * 
 * (c) Kuan-Cheng,Lai <alk03073135@gmail.com>
 * 
 * @author Peter Lai <alk03073135@gmail.com>
 * @license MIT
 */

namespace Web3p\Secp256k1\Signature;

use GMP;
use Mdanter\Ecc\Crypto\Signature\Signer as EccSigner;
// use Mdanter\Ecc\Crypto\Signature\Signature;
use Mdanter\Ecc\Crypto\Signature\SignatureInterface;
use Mdanter\Ecc\Crypto\Key\PrivateKeyInterface;
use Mdanter\Ecc\Crypto\Key\PublicKeyInterface;
use Mdanter\Ecc\Math\GmpMathInterface;
use Web3p\Secp256k1\Signature\Signature;

class Signer
{
    /**
     * adapter
     *
     * @var \Mdanter\Ecc\Math\GmpMathInterface
     */
    protected $adapter;

    /**
     * signer
     *
     * @var \Mdanter\Ecc\Crypto\Signature\Signer
     */
    protected $signer;

    /**
     * options
     * 
     * @var array
     */
    protected $options;

    /**
     * construct
     *
     * @param \Mdanter\Ecc\Math\GmpMathInterface $adapter
     * @param array options
     * @return void
     */
    public function __construct(GmpMathInterface $adapter, array $options=[])
    {
        $this->adapter = $adapter;
        $this->signer = new EccSigner($adapter);
        $this->options = $options;
    }

    /**
     * sign
     * maybe copy original code
     * 
     * @param \Mdanter\Ecc\Crypto\Key\PrivateKeyInterface $key
     * @param \GMP $truncatedHash - hash truncated for use in ECDSA
     * @param \GMP $randomK
     * @return \Mdanter\Ecc\Crypto\Signature\SignatureInterface
     */
    public function sign(PrivateKeyInterface $key, GMP $truncatedHash, GMP $randomK): SignatureInterface
    {
        $signature = $this->signer->sign($key, $truncatedHash, $randomK);
        $options = $this->options;
        $math = $this->adapter;

        // get r and s
        $r = $signature->getR();
        $s = $signature->getS();

        // get recovery param
        $zero = gmp_init(0, 10);
        $two = gmp_init(2, 10);
        $generator = $key->getPoint();
        $kp = $generator->mul($randomK);
        $kpY = $kp->getY();
        $kpX = $kp->getX();
        $recoveryParam = (($math->equals($math->mod($kpY, $two), $zero)) ? 0 : 1) |
                         (($math->cmp($kpX, $r) !== 0)  ? 2 : 0);

        if (
            (isset($options['canonical']) && $options['canonical'] === true) &&
            (isset($options['n']) && $options['n'] instanceof GMP)) {
            $nh = $math->rightShift($options['n'], 1);

            if ($math->cmp($s, $nh) > 0) {
                $s = gmp_sub($options['n'], $s);
                $recoveryParam ^= 1;
            }
        }

        return new Signature($r, $s, $recoveryParam);
    }

    /**
     * @param \Mdanter\Ecc\Crypto\Key\PublicKeyInterface $key
     * @param \Mdanter\Ecc\Crypto\Signature\SignatureInterface $signature
     * @param \GMP $hash
     * @return bool
     */
    public function verify(PublicKeyInterface $key, SignatureInterface $signature, \GMP $hash): bool
    {
        return $this->signer->verify($key, $signature, $hash);
    }
}
