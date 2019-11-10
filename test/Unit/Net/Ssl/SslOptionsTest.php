<?php
namespace ScriptFUSIONTest\Unit\Porter\Net\Ssl;

use ScriptFUSION\Porter\Net\Ssl\SslOptions;

/**
 * @see SslOptions
 */
final class SslOptionsTest extends \PHPUnit_Framework_TestCase
{
    public function testPeerName(): void
    {
        self::assertSame($peerName = 'foo', (new SslOptions)->setPeerName($peerName)->getPeerName());
    }

    public function testVerifyPeer(): void
    {
        self::assertFalse((new SslOptions)->setVerifyPeer(false)->getVerifyPeer());
    }

    public function testVerifyPeerName(): void
    {
        self::assertFalse((new SslOptions)->setVerifyPeerName(false)->getVerifyPeerName());
    }

    public function testAllowSelfSigned(): void
    {
        self::assertTrue((new SslOptions)->setAllowSelfSigned(true)->getAllowSelfSigned());
    }

    public function testCertificateAuthorityFilePath(): void
    {
        self::assertSame(
            $caPath = 'foo',
            (new SslOptions)->setCertificateAuthorityFilePath($caPath)->getCertificateAuthorityFilePath()
        );
    }

    public function testCertificateAuthorityDirectory(): void
    {
        self::assertSame(
            $caDirectory = 'foo',
            (new SslOptions)->setCertificateAuthorityDirectory($caDirectory)->getCertificateAuthorityDirectory()
        );
    }

    public function testCertificateFilePath(): void
    {
        self::assertSame(
            $certPath = 'foo',
            (new SslOptions)->setCertificateFilePath($certPath)->getCertificateFilePath()
        );
    }

    public function testCertificatePassphrase(): void
    {
        self::assertSame($pass = 'foo', (new SslOptions)->setCertificatePassphrase($pass)->getCertificatePassphrase());
    }

    public function testPrivateKeyFilePath(): void
    {
        self::assertSame($pkPath = 'foo', (new SslOptions)->setPrivateKeyFilePath($pkPath)->getPrivateKeyFilePath());
    }

    public function testVerificationDepth(): void
    {
        self::assertSame($depth = 123, (new SslOptions)->setVerificationDepth($depth)->getVerificationDepth());
    }

    public function testCiphers(): void
    {
        self::assertSame($ciphers = 'foo', (new SslOptions)->setCiphers($ciphers)->getCiphers());
    }

    public function testCapturePeerCertificate(): void
    {
        self::assertTrue((new SslOptions)->setCapturePeerCertificate(true)->getCapturePeerCertificate());
    }

    public function testCapturePeerCertificateChain(): void
    {
        self::assertTrue((new SslOptions)->setCapturePeerCertificateChain(true)->getCapturePeerCertificateChain());
    }

    public function testSniEnabled(): void
    {
        self::assertTrue((new SslOptions)->setSniEnabled(true)->getSniEnabled());
    }

    public function testDisableCompression(): void
    {
        self::assertTrue((new SslOptions)->setDisableCompression(true)->getDisableCompression());
    }

    /**
     * @dataProvider providePeerFingerprints
     *
     * @param string|array $fingerprint
     */
    public function testPeerFingerprint($fingerprint): void
    {
        $options = new SslOptions;

        self::assertSame($fingerprint, $options->setPeerFingerprint($fingerprint)->getPeerFingerprint());
    }

    public function providePeerFingerprints(): ?\Generator
    {
        yield 'string' => ['foo'];
        yield 'array' => [['foo' => 'bar']];
    }

    public function testExtractSslContextOptions(): void
    {
        $context = (new SslOptions)
            ->setPeerName($peerName = 'foo')
            ->setVerifyPeer(false)
            ->setVerifyPeerName(false)
            ->setAllowSelfSigned(true)
            ->setCertificateAuthorityFilePath($caPath = 'bar')
            ->setCertificateAuthorityDirectory($caDirectory = 'baz')
            ->setCertificateFilePath($certPath = 'qux')
            ->setCertificatePassphrase($pass = 'quux')
            ->setPrivateKeyFilePath($pkPath = 'corge')
            ->setVerificationDepth($depth = 123)
            ->setCiphers($ciphers = 'grault')
            ->setCapturePeerCertificate(true)
            ->setCapturePeerCertificateChain(true)
            ->setSniEnabled(true)
            ->setDisableCompression(true)
            ->setPeerFingerprint($fingerprint = 'garply')
            ->extractSslContextOptions();

        self::assertSame($peerName, $context['peer_name']);
        self::assertFalse($context['verify_peer']);
        self::assertFalse($context['verify_peer_name']);
        self::assertTrue($context['allow_self_signed']);
        self::assertSame($caPath, $context['cafile']);
        self::assertSame($caDirectory, $context['capath']);
        self::assertSame($certPath, $context['local_cert']);
        self::assertSame($pass, $context['passphrase']);
        self::assertSame($pkPath, $context['local_pk']);
        self::assertSame($depth, $context['verify_depth']);
        self::assertSame($ciphers, $context['ciphers']);
        self::assertTrue($context['capture_peer_cert']);
        self::assertTrue($context['capture_peer_cert_chain']);
        self::assertTrue($context['SNI_enabled']);
        self::assertTrue($context['disable_compression']);
        self::assertSame($fingerprint, $context['peer_fingerprint']);
    }
}
