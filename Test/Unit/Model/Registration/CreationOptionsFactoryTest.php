<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Test\Unit\Model\Registration;

use Cose\Algorithms;
use MageDevGroup\CustomerPasskey\Model\Config;
use MageDevGroup\CustomerPasskey\Model\Registration\CreationOptionsFactory;
use MageDevGroup\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use MageDevGroup\CustomerPasskey\Model\Webauthn\RelyingPartyEntityFactory;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

#[AllowMockObjectsWithoutExpectations]
class CreationOptionsFactoryTest extends TestCase
{
    /** @var Config&MockObject */
    private $config;

    /** @var RelyingPartyEntityFactory&MockObject */
    private $rpFactory;

    /** @var CredentialSourceRepository&MockObject */
    private $sourceRepository;

    /** @var CreationOptionsFactory */
    private CreationOptionsFactory $factory;

    protected function setUp(): void
    {
        $this->config = $this->createMock(Config::class);
        $this->rpFactory = $this->createMock(RelyingPartyEntityFactory::class);
        $this->sourceRepository = $this->createMock(CredentialSourceRepository::class);

        $this->rpFactory->method('create')
            ->willReturn(PublicKeyCredentialRpEntity::create('Acme', 'acme.test'));
        $this->config->method('getTimeout')->willReturn(45000);
        $this->config->method('getUserVerification')->willReturn(Config::USER_VERIFICATION_REQUIRED);
        $this->config->method('getAuthenticatorAttachment')->willReturn(Config::ATTACHMENT_ANY);
        $this->config->method('isPasswordlessAllowed')->willReturn(false);

        $this->factory = new CreationOptionsFactory(
            $this->config,
            $this->rpFactory,
            $this->sourceRepository
        );
    }

    private function source(string $rawId, array $transports = []): PublicKeyCredentialSource
    {
        return PublicKeyCredentialSource::create(
            $rawId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $transports,
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString('00000000-0000-0000-0000-000000000000'),
            'cose-key',
            '42',
            0
        );
    }

    public function testBuildsOptionsShapeForCustomer(): void
    {
        $this->sourceRepository->method('findAllForUserEntity')->willReturn([]);

        $options = $this->factory->create(42, 'shopper@acme.test', 'Jane Shopper');

        self::assertSame('acme.test', $options->rp->id);
        self::assertSame('42', $options->user->id);
        self::assertSame('shopper@acme.test', $options->user->name);
        self::assertSame('Jane Shopper', $options->user->displayName);
        self::assertSame(45000, $options->timeout);
        self::assertSame(
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            $options->attestation
        );
        self::assertSame(32, strlen($options->challenge));

        $algorithms = array_map(
            static fn(PublicKeyCredentialParameters $p): int => $p->alg,
            $options->pubKeyCredParams
        );
        self::assertSame([Algorithms::COSE_ALGORITHM_ES256, Algorithms::COSE_ALGORITHM_RS256], $algorithms);
    }

    public function testUserVerificationAndAttachmentComeFromConfig(): void
    {
        $this->sourceRepository->method('findAllForUserEntity')->willReturn([]);

        $options = $this->factory->create(42, 'shopper@acme.test', 'Jane Shopper');

        self::assertSame(
            Config::USER_VERIFICATION_REQUIRED,
            $options->authenticatorSelection->userVerification
        );
        // "any" attachment maps to no preference (criterion omitted).
        self::assertNull($options->authenticatorSelection->authenticatorAttachment);
        self::assertSame(
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE,
            $options->authenticatorSelection->residentKey
        );
    }

    public function testPlatformAttachmentAndPasswordlessRequestResidentKey(): void
    {
        $config = $this->createMock(Config::class);
        $config->method('getTimeout')->willReturn(60000);
        $config->method('getUserVerification')->willReturn(Config::USER_VERIFICATION_PREFERRED);
        $config->method('getAuthenticatorAttachment')->willReturn(Config::ATTACHMENT_PLATFORM);
        $config->method('isPasswordlessAllowed')->willReturn(true);
        $this->sourceRepository->method('findAllForUserEntity')->willReturn([]);

        $factory = new CreationOptionsFactory($config, $this->rpFactory, $this->sourceRepository);
        $options = $factory->create(7, 'a@b.test', 'A B');

        self::assertSame(
            AuthenticatorSelectionCriteria::AUTHENTICATOR_ATTACHMENT_PLATFORM,
            $options->authenticatorSelection->authenticatorAttachment
        );
        self::assertSame(
            AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED,
            $options->authenticatorSelection->residentKey
        );
    }

    public function testExcludeCredentialsPopulatedFromExistingPasskeys(): void
    {
        $this->sourceRepository->expects(self::once())
            ->method('findAllForUserEntity')
            ->with(self::callback(static fn($user): bool => $user->id === '42'))
            ->willReturn([
                $this->source('raw-id-one', ['internal']),
                $this->source('raw-id-two', ['hybrid', 'usb']),
            ]);

        $options = $this->factory->create(42, 'shopper@acme.test', 'Jane Shopper');

        self::assertCount(2, $options->excludeCredentials);
        self::assertContainsOnlyInstancesOf(
            PublicKeyCredentialDescriptor::class,
            $options->excludeCredentials
        );
        self::assertSame('raw-id-one', $options->excludeCredentials[0]->id);
        self::assertSame(['internal'], $options->excludeCredentials[0]->transports);
        self::assertSame('raw-id-two', $options->excludeCredentials[1]->id);
        self::assertSame(['hybrid', 'usb'], $options->excludeCredentials[1]->transports);
    }

    public function testChallengeIsFreshEachCall(): void
    {
        $this->sourceRepository->method('findAllForUserEntity')->willReturn([]);

        $first = $this->factory->create(42, 'a@b.test', 'A B')->challenge;
        $second = $this->factory->create(42, 'a@b.test', 'A B')->challenge;

        self::assertNotSame($first, $second);
    }
}
