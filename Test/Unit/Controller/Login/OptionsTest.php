<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Test\Unit\Controller\Login;

use MageDevGroup\CustomerPasskey\Controller\Login\Options;
use MageDevGroup\CustomerPasskey\Model\Authentication\RequestOptionsFactory;
use MageDevGroup\CustomerPasskey\Model\Config;
use MageDevGroup\CustomerPasskey\Model\Security\RateLimiter;
use MageDevGroup\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use MageDevGroup\CustomerPasskey\Model\Webauthn\OptionsSerializer;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use Magento\Framework\Exception\NoSuchEntityException;
use Magento\Store\Api\Data\StoreInterface;
use Magento\Store\Model\StoreManagerInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Webauthn\PublicKeyCredentialRequestOptions;

#[AllowMockObjectsWithoutExpectations]
class OptionsTest extends TestCase
{
    /** @var Config&MockObject */
    private $config;

    /** @var RequestOptionsFactory&MockObject */
    private $optionsFactory;

    /** @var ChallengeStorage&MockObject */
    private $challengeStorage;

    /** @var OptionsSerializer&MockObject */
    private $serializer;

    /** @var CustomerRepositoryInterface&MockObject */
    private $customerRepository;

    /** @var StoreManagerInterface&MockObject */
    private $storeManager;

    /** @var RequestInterface&MockObject */
    private $request;

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
        $this->optionsFactory = $this->createMock(RequestOptionsFactory::class);
        $this->challengeStorage = $this->createMock(ChallengeStorage::class);
        $this->serializer = $this->createMock(OptionsSerializer::class);
        $this->customerRepository = $this->createMock(CustomerRepositoryInterface::class);
        $this->storeManager = $this->createMock(StoreManagerInterface::class);
        $this->request = $this->createMock(RequestInterface::class);
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
            $this->optionsFactory,
            $this->challengeStorage,
            $this->serializer,
            $this->customerRepository,
            $this->storeManager,
            $this->request,
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

    private function options(string $challenge): PublicKeyCredentialRequestOptions
    {
        return PublicKeyCredentialRequestOptions::create($challenge, 'acme.test');
    }

    public function testRefusesWhenDisabled(): void
    {
        $this->config->method('isEnabled')->willReturn(false);

        $this->optionsFactory->expects(self::never())->method('create');
        $this->challengeStorage->expects(self::never())->method('save');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(403);
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === false));

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testThrottlesAfterTooManyAttempts(): void
    {
        $this->config->method('isEnabled')->willReturn(true);

        $limiter = $this->createMock(RateLimiter::class);
        $limiter->method('registerAttempt')->willReturn(false);
        $controller = new Options(
            $this->config,
            $this->optionsFactory,
            $this->challengeStorage,
            $this->serializer,
            $this->customerRepository,
            $this->storeManager,
            $this->request,
            $this->jsonFactory(),
            $this->logger,
            $limiter
        );

        $this->optionsFactory->expects(self::never())->method('create');
        $this->challengeStorage->expects(self::never())->method('save');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(429);

        self::assertSame($this->json, $controller->execute());
    }

    public function testDiscoverableRejectedWhenPasswordlessDisabledAndNoEmail(): void
    {
        $this->config->method('isEnabled')->willReturn(true);
        $this->config->method('isPasswordlessAllowed')->willReturn(false);
        $this->request->method('getParam')->with('email', '')->willReturn('');

        $this->optionsFactory->expects(self::never())->method('create');
        $this->challengeStorage->expects(self::never())->method('save');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(400);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testDiscoverableOptionsWhenPasswordlessEnabled(): void
    {
        $this->config->method('isEnabled')->willReturn(true);
        $this->config->method('isPasswordlessAllowed')->willReturn(true);
        $this->request->method('getParam')->with('email', '')->willReturn('');

        $this->customerRepository->expects(self::never())->method('get');
        $this->optionsFactory->expects(self::once())->method('create')->with(null)
            ->willReturn($this->options('disc-challenge'));
        // Discoverable login is unscoped — any resident key may assert.
        $this->challengeStorage->expects(self::once())->method('save')->with('disc-challenge', null);

        $serialized = ['challenge' => 'ZGlzYw', 'rpId' => 'acme.test'];
        $this->serializer->method('toArray')->willReturn($serialized);
        $this->json->expects(self::once())->method('setData')->with($serialized);
        $this->json->expects(self::never())->method('setHttpResponseCode');

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testEmailFirstResolvesCustomerAndPersistsChallenge(): void
    {
        $this->config->method('isEnabled')->willReturn(true);
        $this->config->method('isPasswordlessAllowed')->willReturn(false);
        $this->request->method('getParam')->with('email', '')->willReturn('shopper@acme.test');

        $store = $this->createMock(StoreInterface::class);
        $store->method('getWebsiteId')->willReturn(1);
        $this->storeManager->method('getStore')->willReturn($store);

        $customer = $this->createMock(CustomerInterface::class);
        $customer->method('getId')->willReturn(42);
        $this->customerRepository->expects(self::once())->method('get')
            ->with('shopper@acme.test', 1)->willReturn($customer);

        $this->optionsFactory->expects(self::once())->method('create')->with(42)
            ->willReturn($this->options('email-challenge'));
        // Email-first binds the request to the resolved account for the verify step.
        $this->challengeStorage->expects(self::once())->method('save')->with('email-challenge', 42);

        $serialized = ['challenge' => 'ZW1haWw', 'allowCredentials' => [['type' => 'public-key', 'id' => 'x']]];
        $this->serializer->method('toArray')->willReturn($serialized);
        $this->json->expects(self::once())->method('setData')->with($serialized);
        $this->json->expects(self::never())->method('setHttpResponseCode');

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testUnknownEmailFallsBackToDiscoverableWithoutLeaking(): void
    {
        $this->config->method('isEnabled')->willReturn(true);
        $this->config->method('isPasswordlessAllowed')->willReturn(false);
        $this->request->method('getParam')->with('email', '')->willReturn('ghost@acme.test');

        $store = $this->createMock(StoreInterface::class);
        $store->method('getWebsiteId')->willReturn(1);
        $this->storeManager->method('getStore')->willReturn($store);

        $this->customerRepository->method('get')
            ->willThrowException(new NoSuchEntityException(__('No such entity.')));

        // Unknown email resolves to null → discoverable options, indistinguishable
        // from a known account with no passkeys. No error is emitted, but the request
        // is scoped to 0 so the verify step rejects any asserted credential.
        $this->optionsFactory->expects(self::once())->method('create')->with(null)
            ->willReturn($this->options('ghost-challenge'));
        $this->challengeStorage->expects(self::once())->method('save')->with('ghost-challenge', 0);
        $this->serializer->method('toArray')->willReturn(['challenge' => 'Z2hvc3Q']);
        $this->json->expects(self::never())->method('setHttpResponseCode');

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testReportsFailureWithoutLeakingDetails(): void
    {
        $this->config->method('isEnabled')->willReturn(true);
        $this->config->method('isPasswordlessAllowed')->willReturn(true);
        $this->request->method('getParam')->with('email', '')->willReturn('');
        $this->optionsFactory->method('create')->willThrowException(new \RuntimeException('boom'));

        $this->challengeStorage->expects(self::never())->method('save');
        $this->logger->expects(self::once())->method('critical');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(500);
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === false));

        self::assertSame($this->json, $this->controller->execute());
    }
}
