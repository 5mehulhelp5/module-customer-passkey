<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Test\Unit\Model\Authentication;

use MageDevGroup\CustomerPasskey\Model\Authentication\RequestOptionsFactory;
use MageDevGroup\CustomerPasskey\Model\Config;
use MageDevGroup\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

#[AllowMockObjectsWithoutExpectations]
class RequestOptionsFactoryTest extends TestCase
{
    /** @var Config&MockObject */
    private $config;

    /** @var CredentialSourceRepository&MockObject */
    private $sourceRepository;

    /** @var RequestOptionsFactory */
    private RequestOptionsFactory $factory;

    protected function setUp(): void
    {
        $this->config = $this->createMock(Config::class);
        $this->sourceRepository = $this->createMock(CredentialSourceRepository::class);

        $this->config->method('getRpId')->willReturn('acme.test');
        $this->config->method('getUserVerification')->willReturn(Config::USER_VERIFICATION_REQUIRED);
        $this->config->method('getTimeout')->willReturn(45000);

        $this->factory = new RequestOptionsFactory($this->config, $this->sourceRepository);
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

    public function testDiscoverableOptionsHaveEmptyAllowCredentials(): void
    {
        $this->sourceRepository->expects(self::never())->method('findAllForUserEntity');

        $options = $this->factory->create();

        self::assertSame('acme.test', $options->rpId);
        self::assertSame(Config::USER_VERIFICATION_REQUIRED, $options->userVerification);
        self::assertSame(45000, $options->timeout);
        self::assertSame([], $options->allowCredentials);
        self::assertSame(32, strlen($options->challenge));
    }

    public function testEmailFirstOptionsScopeAllowCredentialsToCustomer(): void
    {
        $this->sourceRepository->expects(self::once())
            ->method('findAllForUserEntity')
            ->with(self::callback(static fn($user): bool => $user->id === '42'))
            ->willReturn([
                $this->source('raw-id-one', ['internal']),
                $this->source('raw-id-two', ['hybrid', 'usb']),
            ]);

        $options = $this->factory->create(42);

        self::assertCount(2, $options->allowCredentials);
        self::assertContainsOnlyInstancesOf(
            PublicKeyCredentialDescriptor::class,
            $options->allowCredentials
        );
        self::assertSame('raw-id-one', $options->allowCredentials[0]->id);
        self::assertSame(['internal'], $options->allowCredentials[0]->transports);
        self::assertSame('raw-id-two', $options->allowCredentials[1]->id);
    }

    public function testCustomerWithoutPasskeysGetsEmptyAllowCredentials(): void
    {
        $this->sourceRepository->method('findAllForUserEntity')->willReturn([]);

        $options = $this->factory->create(7);

        self::assertSame([], $options->allowCredentials);
    }

    public function testNonPositiveCustomerIdIsTreatedAsDiscoverable(): void
    {
        $this->sourceRepository->expects(self::never())->method('findAllForUserEntity');

        $options = $this->factory->create(0);

        self::assertSame([], $options->allowCredentials);
    }

    public function testRpIdIsNullWhenHostUnresolvable(): void
    {
        $config = $this->createMock(Config::class);
        $config->method('getRpId')->willReturn('');
        $config->method('getUserVerification')->willReturn(Config::USER_VERIFICATION_PREFERRED);
        $config->method('getTimeout')->willReturn(60000);

        $factory = new RequestOptionsFactory($config, $this->sourceRepository);
        $options = $factory->create();

        self::assertNull($options->rpId);
    }

    public function testChallengeIsFreshEachCall(): void
    {
        $this->sourceRepository->method('findAllForUserEntity')->willReturn([]);

        $first = $this->factory->create()->challenge;
        $second = $this->factory->create()->challenge;

        self::assertNotSame($first, $second);
    }
}
