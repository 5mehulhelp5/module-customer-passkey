<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Controller\Register;

use DmLab\CustomerPasskey\Controller\Register\Options;
use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Registration\CreationOptionsFactory;
use DmLab\CustomerPasskey\Model\Security\RateLimiter;
use DmLab\CustomerPasskey\Model\Security\RecentAuthentication;
use DmLab\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use DmLab\CustomerPasskey\Model\Webauthn\OptionsSerializer;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Customer\Model\Session;
use Magento\Framework\App\RequestInterface;
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

    /** @var RecentAuthentication&MockObject */
    private $recent;

    /** @var RequestInterface&MockObject */
    private $request;

    /** @var bool whether the session is within the re-authentication window */
    private bool $fresh = true;

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
        $this->fresh = true;
        $this->recent = $this->createMock(RecentAuthentication::class);
        $this->recent->method('isFresh')->willReturnCallback(fn(): bool => $this->fresh);
        $this->request = $this->createMock(RequestInterface::class);

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
            $this->rateLimiter,
            $this->recent,
            $this->request
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
            PublicKeyCredentialRpEntity::create('', 'acme.test'),
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
            $this->rateLimiter,
            $this->recent,
            $this->request
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
        $this->fresh = false;
        $this->request->method('getParam')->with('password', '')->willReturn('guess');
        $this->recent->expects(self::never())->method('confirmPassword');

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
            $limiter,
            $this->recent,
            $this->request
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

        $this->challengeStorage->expects(self::once())->method('save')
            ->with(ChallengeStorage::CEREMONY_REGISTER, 'raw-challenge', 42);

        $serialized = ['rp' => ['id' => 'acme.test'], 'challenge' => 'cmF3'];
        $this->serializer->method('toArray')->willReturn($serialized);
        $this->json->expects(self::once())->method('setData')->with($serialized);
        $this->json->expects(self::never())->method('setHttpResponseCode');

        self::assertSame($this->json, $this->controller->execute());
    }

    private function loggedInCustomer(): void
    {
        $customer = $this->createStub(CustomerInterface::class);
        $customer->method('getEmail')->willReturn('shopper@acme.test');
        $customer->method('getFirstname')->willReturn('Jane');
        $customer->method('getLastname')->willReturn('Shopper');

        $this->session->method('isLoggedIn')->willReturn(true);
        $this->session->method('getCustomerId')->willReturn(42);
        $this->session->method('getCustomerData')->willReturn($customer);
    }

    public function testStaleSessionWithoutPasswordAsksToReauthenticate(): void
    {
        $this->loggedInCustomer();
        $this->fresh = false;
        $this->request->method('getParam')->with('password', '')->willReturn('');

        $this->recent->expects(self::never())->method('confirmPassword');
        $this->recent->expects(self::never())->method('markNow');
        $this->optionsFactory->expects(self::never())->method('create');
        $this->challengeStorage->expects(self::never())->method('save');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(401);
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === false
                && $d['reauth'] === true
                && (string)$d['message'] !== ''));

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testStaleSessionWithWrongPasswordIsRefused(): void
    {
        $this->loggedInCustomer();
        $this->fresh = false;
        $this->request->method('getParam')->with('password', '')->willReturn('wrong');

        $this->recent->expects(self::once())->method('confirmPassword')
            ->with(42, 'wrong')
            ->willReturn(false);
        $this->recent->expects(self::never())->method('markNow');
        $this->optionsFactory->expects(self::never())->method('create');
        $this->challengeStorage->expects(self::never())->method('save');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(401);
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['reauth'] === true));

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testStaleSessionWithRightPasswordReturnsOptionsAndMarks(): void
    {
        $this->loggedInCustomer();
        $this->fresh = false;
        $this->request->method('getParam')->with('password', '')->willReturn('secret');

        $this->recent->expects(self::once())->method('confirmPassword')
            ->with(42, 'secret')
            ->willReturn(true);
        $this->recent->expects(self::once())->method('markNow');
        $this->optionsFactory->expects(self::once())->method('create')
            ->willReturn($this->options('raw-challenge'));
        $this->challengeStorage->expects(self::once())->method('save')
            ->with(ChallengeStorage::CEREMONY_REGISTER, 'raw-challenge', 42);

        $serialized = ['challenge' => 'cmF3'];
        $this->serializer->method('toArray')->willReturn($serialized);
        $this->json->expects(self::once())->method('setData')->with($serialized);
        $this->json->expects(self::never())->method('setHttpResponseCode');

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testFreshSessionSkipsPasswordCheck(): void
    {
        $this->loggedInCustomer();

        $this->request->expects(self::never())->method('getParam');
        $this->recent->expects(self::never())->method('confirmPassword');
        $this->optionsFactory->method('create')->willReturn($this->options('raw-challenge'));
        $this->serializer->method('toArray')->willReturn([]);
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
