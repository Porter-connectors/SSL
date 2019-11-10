<?php
declare(strict_types=1);

namespace ScriptFUSION\Porter\Net\Ssl;

final class SslOptions
{
    /** @var string|null */
    private $peerName;

    private $verifyPeer = true;

    private $verifyPerName = true;

    private $allowSelfSigned = false;

    /** @var string|null */
    private $certificateAuthorityFilePath;

    /** @var string|null */
    private $certificateAuthorityDirectory;

    /** @var string|null */
    private $certificateFilePath;

    /** @var string|null */
    private $certificatePassphrase;

    /** @var string|null */
    private $privateKeyFilePath;

    /** @var int|null */
    private $verificationDepth;

    private $ciphers = 'DEFAULT';

    /** @var bool|null */
    private $capturePeerCertificate;

    /** @var bool|null */
    private $capturePeerCertificateChain;

    /** @var bool|null */
    private $sniEnabled;

    /** @var bool|null */
    private $disableCompression;

    /** @var string|array */
    private $peerFingerprint;

    public function getPeerName(): ?string
    {
        return $this->peerName;
    }

    public function setPeerName(?string $peerName): self
    {
        $this->peerName = $peerName;

        return $this;
    }

    public function getVerifyPeer(): bool
    {
        return $this->verifyPeer;
    }

    public function setVerifyPeer(bool $verifyPeer): self
    {
        $this->verifyPeer = $verifyPeer;

        return $this;
    }

    public function getVerifyPeerName(): bool
    {
        return $this->verifyPerName;
    }

    public function setVerifyPeerName(bool $verifyPeerName): self
    {
        $this->verifyPerName = $verifyPeerName;

        return $this;
    }

    public function getAllowSelfSigned(): bool
    {
        return $this->allowSelfSigned;
    }

    public function setAllowSelfSigned(bool $allowSelfSigned): self
    {
        $this->allowSelfSigned = $allowSelfSigned;

        return $this;
    }

    public function getCertificateAuthorityFilePath(): ?string
    {
        return $this->certificateAuthorityFilePath;
    }

    public function setCertificateAuthorityFilePath(?string $certificateAuthorityFilePath): self
    {
        $this->certificateAuthorityFilePath = $certificateAuthorityFilePath;

        return $this;
    }

    public function getCertificateAuthorityDirectory(): ?string
    {
        return $this->certificateAuthorityDirectory;
    }

    public function setCertificateAuthorityDirectory(?string $certificateAuthorityDirectory): self
    {
        $this->certificateAuthorityDirectory = $certificateAuthorityDirectory;

        return $this;
    }

    public function getCertificateFilePath(): ?string
    {
        return $this->certificateFilePath;
    }

    public function setCertificateFilePath(?string $certificateFilePath): self
    {
        $this->certificateFilePath = $certificateFilePath;

        return $this;
    }

    public function getCertificatePassphrase(): ?string
    {
        return $this->certificatePassphrase;
    }

    public function setCertificatePassphrase(?string $certificatePassphrase): self
    {
        $this->certificatePassphrase = $certificatePassphrase;

        return $this;
    }

    public function getPrivateKeyFilePath(): ?string
    {
        return $this->privateKeyFilePath;
    }

    public function setPrivateKeyFilePath(?string $privateKeyFilePath): self
    {
        $this->privateKeyFilePath = $privateKeyFilePath;

        return $this;
    }

    public function getVerificationDepth(): ?int
    {
        return $this->verificationDepth;
    }

    public function setVerificationDepth(?int $verificationDepth): self
    {
        $this->verificationDepth = $verificationDepth;

        return $this;
    }

    public function getCiphers(): string
    {
        return $this->ciphers;
    }

    public function setCiphers(string $ciphers): self
    {
        $this->ciphers = $ciphers;

        return $this;
    }

    public function getCapturePeerCertificate(): ?bool
    {
        return $this->capturePeerCertificate;
    }

    public function setCapturePeerCertificate(?bool $capturePeerCertificate): self
    {
        $this->capturePeerCertificate = $capturePeerCertificate;

        return $this;
    }

    public function getCapturePeerCertificateChain(): ?bool
    {
        return $this->capturePeerCertificateChain;
    }

    public function setCapturePeerCertificateChain(?bool $capturePeerCertificateChain): self
    {
        $this->capturePeerCertificateChain = $capturePeerCertificateChain;

        return $this;
    }

    public function getSniEnabled(): ?bool
    {
        return $this->sniEnabled;
    }

    public function setSniEnabled(?bool $sniEnabled): self
    {
        $this->sniEnabled = $sniEnabled;

        return $this;
    }

    public function getDisableCompression(): ?bool
    {
        return $this->disableCompression;
    }

    public function setDisableCompression(?bool $disableCompression): self
    {
        $this->disableCompression = $disableCompression;

        return $this;
    }

    /**
     * @return array|string
     */
    public function getPeerFingerprint()
    {
        return $this->peerFingerprint;
    }

    /**
     * @param array|string $peerFingerprint
     *
     * @return $this
     */
    public function setPeerFingerprint($peerFingerprint): self
    {
        $this->peerFingerprint = $peerFingerprint;

        return $this;
    }

    public function extractSslContextOptions(): array
    {
        return array_filter([
            'peer_name' => $this->peerName,
            'verify_peer' => $this->verifyPeer,
            'verify_peer_name' => $this->verifyPerName,
            'allow_self_signed' => $this->allowSelfSigned,
            'cafile' => $this->certificateAuthorityFilePath,
            'capath' => $this->certificateAuthorityDirectory,
            'local_cert' => $this->certificateFilePath,
            'local_pk' => $this->privateKeyFilePath,
            'passphrase' => $this->certificatePassphrase,
            'verify_depth' => $this->verificationDepth,
            'ciphers' => $this->ciphers,
            'capture_peer_cert' => $this->capturePeerCertificate,
            'capture_peer_cert_chain' => $this->capturePeerCertificateChain,
            'SNI_enabled' => $this->sniEnabled,
            'disable_compression' => $this->disableCompression,
            'peer_fingerprint' => $this->peerFingerprint,
        ], static function ($v): bool {
            return $v !== null;
        });
    }
}
