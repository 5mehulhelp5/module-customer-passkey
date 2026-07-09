<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Test\Unit\Controller\Register;

use MageDevGroup\CustomerPasskey\Controller\Register\Options;
use MageDevGroup\CustomerPasskey\Model\Config;
use MageDevGroup\CustomerPasskey\Model\Registration\CreationOptionsFactory;
use MageDevGroup\CustomerPasskey\Model\Security\RateLimiter;
use MageDevGroup\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use MageDevGroup\CustomerPasskey\Model\Webauthn\OptionsSerializer;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Customer\Model\Session;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialRpEntity;
use Webauthn\PublicKeyCredentialUserEntity;

#[AllowMockObjectsWithoutExpectations]
class OptionsTest extends TestCase
{
    /** @var Config&MockObject */
    private $config;

    /** @var Session&MockObject */
    private $session;

    /** @var CreationOptionsFactory&MockObject */
    private $optionsFactory;

    /** @var ChallengeStorage&MockObject */
    private $challengeStorage;

    /** @var OptionsSerializer&MockObject */
    private $serializer;

    /** @var Json&MockObject */
    private $json;

    /** @var LoggerInterface&MockObject */
    private $logger;

    /** @var RateLimiter&MockObject */
    private $rateLimiter;

    /** @var Options */
    private Options $controller;

    protected function setUp(): void
    {
        $this->config = $this->createMock(Config::class);
        $this->config->method('isEnabled')->willReturn(true);
        $this->session = $this->createMock(Session::class);
        $this->optionsFactory = $this->createMock(CreationOptionsFactory::class);
        $this->challengeStorage = $this->createMock(ChallengeStorage::class);
        $this->serializer = $this->createMock(OptionsSerializer::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->rateLimiter = $this->createMock(RateLimiter::class);
        $this->rateLimiter->method('registerAttempt')->willReturn(true);

        $this->json = $this->createMock(Json::class);
        $this->json->method('setHttpResponseCode')->willReturnSelf();
        $this->json->method('setData')->willReturnSelf();

        $jsonFactory = $this->createStub(JsonFactory::class);
        $jsonFactory->method('create')->willReturn($this->json);

        $this->controller = new Options(
            $this->config,
            $this->session,
            $this->optionsFactory,
            $this->challengeStorage,
            $this->serializer,
            $jsonFactory,
            $this->logger,
            $this->rateLimiter
        );
    }

    private function jsonFactory(): JsonFactory
    {
        $jsonFactory = $this->createStub(JsonFactory::class);
        $jsonFactory->method('create')->willReturn($this->json);

        return $jsonFactory;
    }

    private function options(string $challenge): PublicKeyCredentialCreationOptions
    {
        return PublicKeyCredentialCreationOptions::create(
            PublicKeyCredentialRpEntity::create('Acme', 'acme.test'),
            PublicKeyCredentialUserEntity::create('shopper@acme.test', '42', 'Jane'),
            $challenge
        );
    }

    public function testRefusesWhenDisabled(): void
    {
        $config = $this->createMock(Config::class);
        $config->method('isEnabled')->willReturn(false);
        $controller = new Options(
            $config,
            $this->session,
            $this->optionsFactory,
            $this->challengeStorage,
            $this->serializer,
            $this->jsonFactory(),
            $this->logger,
            $this->rateLimiter
        );

        $this->session->expects(self::never())->method('isLoggedIn');
        $this->optionsFactory->expects(self::never())->method('create');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(403);

        self::assertSame($this->json, $controller->execute());
    }

    public function testRefusesAnonymousRequest(): void
    {
        $this->session->method('isLoggedIn')->willReturn(false);

        $this->optionsFactory->expects(self::never())->method('create');
        $this->challengeStorage->expects(self::never())->method('save');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(403);
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === false));

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testThrottlesAfterTooManyAttempts(): void
    {
        $this->session->method('isLoggedIn')->willReturn(true);

        $limiter = $this->createMock(RateLimiter::class);
        $limiter->method('registerAttempt')->willReturn(false);
        $controller = new Options(
            $this->config,
            $this->session,
            $this->optionsFactory,
            $this->challengeStorage,
            $this->serializer,
            $this->jsonFactory(),
            $this->logger,
            $limiter
        );

        $this->optionsFactory->expects(self::never())->method('create');
        $this->challengeStorage->expects(self::never())->method('save');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(429);

        self::assertSame($this->json, $controller->execute());
    }

    public function testReturnsOptionsAndPersistsChallengeForLoggedInCustomer(): void
    {
        $customer = $this->createMock(CustomerInterface::class);
        $customer->method('getEmail')->willReturn('shopper@acme.test');
        $customer->method('getFirstname')->willReturn('Jane');
        $customer->method('getLastname')->willReturn('Shopper');

        $this->session->method('isLoggedIn')->willReturn(true);
        $this->session->method('getCustomerId')->willReturn(42);
        $this->session->method('getCustomerData')->willReturn($customer);

        $this->optionsFactory->expects(self::once())->method('create')
            ->with(42, 'shopper@acme.test', 'Jane Shopper')
            ->willReturn($this->options('raw-challenge'));

        $this->challengeStorage->expects(self::once())->method('save')->with('raw-challenge');

        $serialized = ['rp' => ['id' => 'acme.test'], 'challenge' => 'cmF3'];
        $this->serializer->method('toArray')->willReturn($serialized);
        $this->json->expects(self::once())->method('setData')->with($serialized);
        $this->json->expects(self::never())->method('setHttpResponseCode');

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testReportsFailureWithoutLeakingDetails(): void
    {
        $customer = $this->createMock(CustomerInterface::class);
        $customer->method('getEmail')->willReturn('shopper@acme.test');
        $customer->method('getFirstname')->willReturn('Jane');
        $customer->method('getLastname')->willReturn('');

        $this->session->method('isLoggedIn')->willReturn(true);
        $this->session->method('getCustomerId')->willReturn(42);
        $this->session->method('getCustomerData')->willReturn($customer);
        $this->optionsFactory->method('create')->willThrowException(new \RuntimeException('boom'));

        $this->challengeStorage->expects(self::never())->method('save');
        $this->logger->expects(self::once())->method('critical');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(500);
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === false));

        self::assertSame($this->json, $this->controller->execute());
    }
}
