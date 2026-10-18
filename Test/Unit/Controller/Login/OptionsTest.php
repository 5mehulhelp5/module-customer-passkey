<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Controller\Login;

use DmLab\CustomerPasskey\Controller\Login\Options;
use DmLab\CustomerPasskey\Model\Authentication\RequestOptionsFactory;
use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Security\RateLimiter;
use DmLab\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use DmLab\CustomerPasskey\Model\Webauthn\OptionsSerializer;
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
        $this->optionsFactory->expects(self::once())->method('create')->with()
            ->willReturn($this->options('disc-challenge'));
        // Discoverable login is unscoped — any resident key may assert.
        $this->challengeStorage->expects(self::once())->method('save')
            ->with(ChallengeStorage::CEREMONY_LOGIN, 'disc-challenge', null);

        $serialized = ['challenge' => 'ZGlzYw', 'rpId' => 'acme.test'];
        $this->serializer->method('toArray')->willReturn($serialized);
        $this->json->expects(self::once())->method('setData')->with($serialized);
        $this->json->expects(self::never())->method('setHttpResponseCode');

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testEmailScopesChallengeToResolvedCustomer(): void
    {
        $this->config->method('isEnabled')->willReturn(true);
        $this->config->method('isPasswordlessAllowed')->willReturn(false);
        $this->request->method('getParam')->with('email', '')->willReturn('shopper@acme.test');
        $this->stubWebsite();

        $customer = $this->createStub(CustomerInterface::class);
        $customer->method('getId')->willReturn(42);
        $this->customerRepository->expects(self::once())->method('get')
            ->with('shopper@acme.test', 1)->willReturn($customer);

        // The email never reaches the options — only the stored scope.
        $this->optionsFactory->expects(self::once())->method('create')->with()
            ->willReturn($this->options('email-challenge'));
        $this->challengeStorage->expects(self::once())->method('save')
            ->with(ChallengeStorage::CEREMONY_LOGIN, 'email-challenge', 42);
        $this->serializer->method('toArray')->willReturn(['challenge' => 'ZW1haWw']);
        $this->json->expects(self::never())->method('setHttpResponseCode');

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testUnknownEmailScopesChallengeToZero(): void
    {
        $this->config->method('isEnabled')->willReturn(true);
        $this->config->method('isPasswordlessAllowed')->willReturn(false);
        $this->request->method('getParam')->with('email', '')->willReturn('ghost@acme.test');
        $this->stubWebsite();

        $this->customerRepository->method('get')
            ->willThrowException(new NoSuchEntityException(__('No such entity.')));

        // Scope 0 makes the verify step reject any asserted credential.
        $this->optionsFactory->expects(self::once())->method('create')->with()
            ->willReturn($this->options('ghost-challenge'));
        $this->challengeStorage->expects(self::once())->method('save')
            ->with(ChallengeStorage::CEREMONY_LOGIN, 'ghost-challenge', 0);
        $this->serializer->method('toArray')->willReturn(['challenge' => 'Z2hvc3Q']);
        $this->json->expects(self::never())->method('setHttpResponseCode');

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testKnownAndUnknownEmailYieldIdenticalPayload(): void
    {
        $known = $this->runForEmail('shopper@acme.test', 42);
        $unknown = $this->runForEmail('ghost@acme.test', null);

        unset($known['payload']['challenge'], $unknown['payload']['challenge']);
        self::assertSame($known['payload'], $unknown['payload']);
        self::assertArrayNotHasKey('allowCredentials', $known['payload']);
        self::assertArrayNotHasKey('allowCredentials', $unknown['payload']);
        self::assertSame(42, $known['scope']);
        self::assertSame(0, $unknown['scope']);
    }

    /**
     * Run the controller for one email against the real serializer and capture
     * the response payload and the stored challenge scope.
     *
     * @return array{payload: array<string, mixed>, scope: int|null}
     */
    private function runForEmail(string $email, ?int $customerId): array
    {
        $config = $this->createStub(Config::class);
        $config->method('isEnabled')->willReturn(true);
        $config->method('isPasswordlessAllowed')->willReturn(false);
        $config->method('getRpId')->willReturn('acme.test');
        $config->method('getUserVerification')->willReturn(Config::USER_VERIFICATION_PREFERRED);
        $config->method('getTimeout')->willReturn(60000);

        $request = $this->createStub(RequestInterface::class);
        $request->method('getParam')->willReturn($email);

        $repository = $this->createStub(CustomerRepositoryInterface::class);
        if ($customerId === null) {
            $repository->method('get')->willThrowException(new NoSuchEntityException(__('No such entity.')));
        } else {
            $customer = $this->createStub(CustomerInterface::class);
            $customer->method('getId')->willReturn($customerId);
            $repository->method('get')->willReturn($customer);
        }

        $store = $this->createStub(StoreInterface::class);
        $store->method('getWebsiteId')->willReturn(1);
        $storeManager = $this->createStub(StoreManagerInterface::class);
        $storeManager->method('getStore')->willReturn($store);

        $captured = ['payload' => [], 'scope' => null];
        $storage = $this->createStub(ChallengeStorage::class);
        $storage->method('save')->willReturnCallback(
            static function (string $ceremony, string $challenge, ?int $scope) use (&$captured): void {
                $captured['scope'] = $scope;
            }
        );

        $json = $this->createStub(Json::class);
        $json->method('setData')->willReturnCallback(
            static function (array $data) use (&$captured, $json): Json {
                $captured['payload'] = $data;
                return $json;
            }
        );
        $jsonFactory = $this->createStub(JsonFactory::class);
        $jsonFactory->method('create')->willReturn($json);

        $limiter = $this->createStub(RateLimiter::class);
        $limiter->method('registerAttempt')->willReturn(true);

        (new Options(
            $config,
            new RequestOptionsFactory($config),
            $storage,
            new OptionsSerializer($config),
            $repository,
            $storeManager,
            $request,
            $jsonFactory,
            $this->createStub(LoggerInterface::class),
            $limiter
        ))->execute();

        return $captured;
    }

    private function stubWebsite(): void
    {
        $store = $this->createStub(StoreInterface::class);
        $store->method('getWebsiteId')->willReturn(1);
        $this->storeManager->method('getStore')->willReturn($store);
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
