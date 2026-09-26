<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Webauthn;

use DmLab\CustomerPasskey\Model\Webauthn\OptionsSerializer;
use PHPUnit\Framework\TestCase;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

class OptionsSerializerTest extends TestCase
{
    public function testSerializesCreationOptionsToBrowserJsonShape(): void
    {
        $options = PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('Acme', 'acme.test'),
            PublicKeyCredentialUserEntity::create('shopper@acme.test', '42', 'Jane Shopper'),
            'challenge-bytes',
            [PublicKeyCredentialParameters::createPk(-7)],
            null,
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE
        );

        $array = (new OptionsSerializer())->toArray($options);

        self::assertSame('acme.test', $array['rp']['id']);
        self::assertSame('Acme', $array['rp']['name']);
        self::assertSame('Jane Shopper', $array['user']['displayName']);
        self::assertSame('none', $array['attestation']);
        self::assertArrayHasKey('challenge', $array);
        self::assertArrayHasKey('pubKeyCredParams', $array);
        // Challenge is base64url-encoded (unpadded) for the browser.
        self::assertSame('challenge-bytes', $this->base64UrlDecode($array['challenge']));
        // User id round-trips through base64url as well.
        self::assertSame('42', $this->base64UrlDecode($array['user']['id']));
    }

    public function testSerializesRequestOptionsToBrowserJsonShape(): void
    {
        $options = PublicKeyCredentialRequestOptions::create(
            'assert-challenge',
            'acme.test',
            [PublicKeyCredentialDescriptor::create(
                PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
                'raw-cred-id',
                ['internal', 'hybrid']
            )],
            PublicKeyCredentialRequestOptions::USER_VERIFICATION_REQUIREMENT_REQUIRED,
            45000
        );

        $array = (new OptionsSerializer())->toArray($options);

        self::assertSame('acme.test', $array['rpId']);
        self::assertSame('required', $array['userVerification']);
        self::assertSame(45000, $array['timeout']);
        self::assertSame('assert-challenge', $this->base64UrlDecode($array['challenge']));
        self::assertCount(1, $array['allowCredentials']);
        self::assertSame('public-key', $array['allowCredentials'][0]['type']);
        self::assertSame('raw-cred-id', $this->base64UrlDecode($array['allowCredentials'][0]['id']));
        self::assertSame(['internal', 'hybrid'], $array['allowCredentials'][0]['transports']);
    }

    public function testOmitsEmptyAllowCredentialsForDiscoverableRequest(): void
    {
        $options = PublicKeyCredentialRequestOptions::create('c', 'acme.test');

        $array = (new OptionsSerializer())->toArray($options);

        self::assertArrayNotHasKey('allowCredentials', $array);
        self::assertArrayNotHasKey('timeout', $array);
    }

    public function testRejectsUnsupportedOptionsType(): void
    {
        $this->expectException(\InvalidArgumentException::class);

        (new OptionsSerializer())->toArray(
            $this->createStub(\Webauthn\PublicKeyCredentialOptions::class)
        );
    }

    private function base64UrlDecode(string $value): string
    {
        return (string)base64_decode(strtr($value, '-_', '+/'), true);
    }
}
