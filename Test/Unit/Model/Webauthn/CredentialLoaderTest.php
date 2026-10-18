<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Webauthn;

use DmLab\CustomerPasskey\Model\Webauthn\CredentialLoader;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Webauthn\AuthenticatorAssertionResponse;
use Webauthn\AuthenticatorAttestationResponse;

class CredentialLoaderTest extends TestCase
{
    private const RAW_ID = 'raw-credential-id';

    /** @var CredentialLoader */
    private CredentialLoader $loader;

    protected function setUp(): void
    {
        $this->loader = new CredentialLoader();
    }

    public function testLoadsAssertion(): void
    {
        $credential = $this->loader->load($this->assertionPayload());

        self::assertSame(self::RAW_ID, $credential->rawId);
        self::assertInstanceOf(AuthenticatorAssertionResponse::class, $credential->response);
        self::assertSame('42', $credential->response->userHandle);
        self::assertSame(7, $credential->response->authenticatorData->signCount);
        self::assertSame('webauthn.get', $credential->response->clientDataJSON->type);
    }

    public function testLoadsNoneAttestation(): void
    {
        $credential = $this->loader->load($this->attestationPayload());

        self::assertSame(self::RAW_ID, $credential->rawId);
        self::assertInstanceOf(AuthenticatorAttestationResponse::class, $credential->response);
        self::assertSame('none', $credential->response->attestationObject->attStmt->fmt);
        self::assertSame(['internal'], $credential->response->transports);
        self::assertSame(
            self::RAW_ID,
            $credential->response->attestationObject->authData->attestedCredentialData?->credentialId
        );
    }

    /**
     * @return iterable<string,array{callable(array<string,mixed>):array<string,mixed>}>
     */
    public static function malformedPayloads(): iterable
    {
        yield 'non public-key type' => [static fn(array $p): array => ['type' => 'password'] + $p];
        yield 'missing rawId' => [static function (array $p): array {
            unset($p['rawId']);
            return $p;
        }];
        yield 'non-string id' => [static fn(array $p): array => ['id' => 42] + $p];
        yield 'non-array response' => [static fn(array $p): array => ['response' => 'x'] + $p];
        yield 'id and rawId differ' => [static fn(array $p): array => ['id' => 'b3RoZXI'] + $p];
        yield 'unknown response kind' => [static fn(array $p): array => ['response' => ['clientDataJSON' => '']] + $p];
    }

    /**
     * @param callable(array<string,mixed>):array<string,mixed> $mutate
     */
    #[DataProvider('malformedPayloads')]
    public function testRejectsMalformedPayload(callable $mutate): void
    {
        $this->expectException(\Throwable::class);

        $this->loader->load($mutate($this->assertionPayload()));
    }

    /**
     * Browser assertion JSON (as passkey-login.js posts it); the signature is not checked here.
     *
     * @return array<string,mixed>
     */
    private function assertionPayload(): array
    {
        return [
            'id' => $this->base64Url(self::RAW_ID),
            'rawId' => $this->base64Url(self::RAW_ID),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => $this->base64Url($this->clientData('webauthn.get')),
                'authenticatorData' => $this->base64Url(hash('sha256', 'acme.test', true) . "\x05" . pack('N', 7)),
                'signature' => $this->base64Url('signature'),
                'userHandle' => $this->base64Url('42'),
            ],
        ];
    }

    /**
     * Browser attestation JSON (as passkey-manage.js posts it) with a `none` statement.
     *
     * @return array<string,mixed>
     */
    private function attestationPayload(): array
    {
        // COSE EC2 P-256 key map {1: 2, 3: -7, -1: 1, -2: x, -3: y}; coordinates are not validated on load.
        $coseKey = "\xa5\x01\x02\x03\x26\x20\x01\x21\x58\x20" . str_repeat("\x01", 32)
            . "\x22\x58\x20" . str_repeat("\x02", 32);
        $authData = hash('sha256', 'acme.test', true) . "\x45" . pack('N', 0)
            . str_repeat("\0", 16) . pack('n', strlen(self::RAW_ID)) . self::RAW_ID . $coseKey;
        // CBOR map {"fmt": "none", "attStmt": {}, "authData": bytes}.
        $attestationObject = "\xa3\x63fmt\x64none\x67attStmt\xa0\x68authData\x58" . chr(strlen($authData)) . $authData;

        return [
            'id' => $this->base64Url(self::RAW_ID),
            'rawId' => $this->base64Url(self::RAW_ID),
            'type' => 'public-key',
            'response' => [
                'clientDataJSON' => $this->base64Url($this->clientData('webauthn.create')),
                'attestationObject' => $this->base64Url($attestationObject),
                'transports' => ['internal'],
            ],
        ];
    }

    /**
     * @param string $type
     */
    private function clientData(string $type): string
    {
        return (string)json_encode([
            'type' => $type,
            'challenge' => $this->base64Url('challenge'),
            'origin' => 'https://acme.test',
        ]);
    }

    /**
     * @param string $raw
     */
    private function base64Url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }
}
