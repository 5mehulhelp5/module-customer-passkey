<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Test\Unit\Controller\Login;

use MageDevGroup\CustomerPasskey\Controller\Login\Verify;
use MageDevGroup\CustomerPasskey\Model\Authentication\AssertionVerifier;
use MageDevGroup\CustomerPasskey\Model\Config;
use MageDevGroup\CustomerPasskey\Model\Security\RateLimiter;
use MageDevGroup\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use MageDevGroup\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Customer\Model\AccountConfirmation;
use Magento\Customer\Model\AuthenticationInterface;
use Magento\Customer\Model\Config\Share;
use Magento\Customer\Model\Session;
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
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

#[AllowMockObjectsWithoutExpectations]
class VerifyTest extends TestCase
{
    private const NIL_AAGUID = '00000000-0000-0000-0000-000000000000';

    /** @var Config&MockObject */
    private $config;

    /** @var Session&MockObject */
    private $session;

    /** @var RequestInterface&MockObject */
    private $request;

    /** @var AssertionVerifier&MockObject */
    private $verifier;

    /** @var ChallengeStorage&MockObject */
    private $challengeStorage;

    /** @var CredentialSourceRepository&MockObject */
    private $sourceRepository;

    /** @var CustomerRepositoryInterface&MockObject */
    private $customerRepository;

    /** @var Json&MockObject */
    private $json;

    /** @var LoggerInterface&MockObject */
    private $logger;

    /** @var RateLimiter&MockObject */
    private $rateLimiter;

    /** @var StoreManagerInterface&MockObject */
    private $storeManager;

    /** @var AuthenticationInterface&MockObject */
    private $authentication;

    /** @var AccountConfirmation&MockObject */
    private $accountConfirmation;

    /** @var Share&MockObject */
    private $shareConfig;

    /** @var Verify */
    private Verify $controller;

    protected function setUp(): void
    {
        $this->config = $this->createMock(Config::class);
        $this->session = $this->createMock(Session::class);
        $this->request = $this->createMock(RequestInterface::class);
        $this->verifier = $this->createMock(AssertionVerifier::class);
        $this->challengeStorage = $this->createMock(ChallengeStorage::class);
        $this->sourceRepository = $this->createMock(CredentialSourceRepository::class);
        $this->customerRepository = $this->createMock(CustomerRepositoryInterface::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->rateLimiter = $this->createMock(RateLimiter::class);
        $this->rateLimiter->method('registerAttempt')->willReturn(true);

        // Eligibility passes by default: same website, not locked, confirmed.
        $store = $this->createStub(StoreInterface::class);
        $store->method('getWebsiteId')->willReturn(1);
        $this->storeManager = $this->createMock(StoreManagerInterface::class);
        $this->storeManager->method('getStore')->willReturn($store);
        $this->authentication = $this->createMock(AuthenticationInterface::class);
        $this->authentication->method('isLocked')->willReturn(false);
        $this->accountConfirmation = $this->createMock(AccountConfirmation::class);
        $this->accountConfirmation->method('isConfirmationRequired')->willReturn(false);
        // Per-website account sharing by default, so the website gate is enforced.
        $this->shareConfig = $this->createMock(Share::class);
        $this->shareConfig->method('isWebsiteScope')->willReturn(true);

        $this->json = $this->createMock(Json::class);
        $this->json->method('setHttpResponseCode')->willReturnSelf();
        $this->json->method('setData')->willReturnSelf();

        $jsonFactory = $this->createStub(JsonFactory::class);
        $jsonFactory->method('create')->willReturn($this->json);

        $this->controller = new Verify(
            $this->config,
            $this->session,
            $this->request,
            $this->verifier,
            $this->challengeStorage,
            $this->sourceRepository,
            $this->customerRepository,
            $jsonFactory,
            $this->logger,
            $this->rateLimiter,
            $this->storeManager,
            $this->authentication,
            $this->accountConfirmation,
            $this->shareConfig
        );
    }

    private function jsonFactory(): JsonFactory
    {
        $jsonFactory = $this->createStub(JsonFactory::class);
        $jsonFactory->method('create')->willReturn($this->json);

        return $jsonFactory;
    }

    private function enabled(): void
    {
        $this->config->method('isEnabled')->willReturn(true);
    }

    private function payload(string $payload = '{"id":"abc","type":"public-key"}'): void
    {
        $this->request->method('getParam')->willReturnMap([
            ['publicKeyCredential', '', $payload],
        ]);
    }

    private function source(string $userHandle = '42'): PublicKeyCredentialSource
    {
        return PublicKeyCredentialSource::create(
            'raw-cred-id',
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString(self::NIL_AAGUID),
            'raw-cose-key',
            $userHandle,
            7
        );
    }

    public function testRefusesWhenDisabled(): void
    {
        $this->config->method('isEnabled')->willReturn(false);

        $this->challengeStorage->expects(self::never())->method('consume');
        $this->verifier->expects(self::never())->method('verify');
        $this->session->expects(self::never())->method('setCustomerDataAsLoggedIn');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(403);
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === false));

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testThrottlesAfterTooManyAttempts(): void
    {
        $this->enabled();

        $limiter = $this->createMock(RateLimiter::class);
        $limiter->method('registerAttempt')->willReturn(false);
        $controller = new Verify(
            $this->config,
            $this->session,
            $this->request,
            $this->verifier,
            $this->challengeStorage,
            $this->sourceRepository,
            $this->customerRepository,
            $this->jsonFactory(),
            $this->logger,
            $limiter,
            $this->storeManager,
            $this->authentication,
            $this->accountConfirmation,
            $this->shareConfig
        );

        $this->challengeStorage->expects(self::never())->method('consume');
        $this->verifier->expects(self::never())->method('verify');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(429);
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === false));

        self::assertSame($this->json, $controller->execute());
    }

    public function testRejectsMalformedPayloadBeforeConsumingChallenge(): void
    {
        $this->enabled();
        $this->payload('not-json');

        $this->challengeStorage->expects(self::never())->method('consume');
        $this->verifier->expects(self::never())->method('verify');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(400);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testRejectsMissingChallenge(): void
    {
        $this->enabled();
        $this->payload();
        $this->challengeStorage->method('consume')->willReturn(null);

        $this->verifier->expects(self::never())->method('verify');
        $this->session->expects(self::never())->method('setCustomerDataAsLoggedIn');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(400);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testRejectsBadSignature(): void
    {
        $this->enabled();
        $this->payload();
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);
        $this->verifier->method('verify')
            ->willThrowException(new \RuntimeException('Invalid signature.'));

        $this->sourceRepository->expects(self::never())->method('saveCredentialSource');
        $this->session->expects(self::never())->method('setCustomerDataAsLoggedIn');
        $this->logger->expects(self::once())->method('critical');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(422);
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === false));

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testRejectsUnknownCredential(): void
    {
        $this->enabled();
        $this->payload();
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);
        $this->verifier->method('verify')
            ->willThrowException(new \InvalidArgumentException('The credential is not registered.'));

        $this->sourceRepository->expects(self::never())->method('saveCredentialSource');
        $this->session->expects(self::never())->method('setCustomerDataAsLoggedIn');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(422);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testFlagsCounterRegression(): void
    {
        $this->enabled();
        $this->payload();
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);
        // The library's counter step throws when the authenticator counter did not
        // advance — a cloned credential.
        $this->verifier->method('verify')
            ->willThrowException(new \RuntimeException('Invalid counter.'));

        $this->sourceRepository->expects(self::never())->method('saveCredentialSource');
        $this->session->expects(self::never())->method('setCustomerDataAsLoggedIn');
        $this->logger->expects(self::once())->method('critical');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(422);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testRejectsWhenOwnerNoLongerExists(): void
    {
        $this->enabled();
        $this->payload();
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);
        $this->verifier->method('verify')->willReturn($this->source());
        $this->customerRepository->method('getById')
            ->willThrowException(new NoSuchEntityException(__('No such entity.')));

        $this->session->expects(self::never())->method('setCustomerDataAsLoggedIn');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(422);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testEstablishesSessionOnValidAssertion(): void
    {
        $this->enabled();
        $this->payload();
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);

        $source = $this->source('42');
        $this->verifier->expects(self::once())->method('verify')
            ->with('raw-challenge', ['id' => 'abc', 'type' => 'public-key'], null)
            ->willReturn($source);

        // The refreshed counter is persisted so a replay of this assertion is caught.
        $this->sourceRepository->expects(self::once())->method('saveCredentialSource')->with($source);

        $customer = $this->eligibleCustomer();
        $this->customerRepository->expects(self::once())->method('getById')->with(42)
            ->willReturn($customer);
        $this->session->expects(self::once())->method('setCustomerDataAsLoggedIn')->with($customer);

        $this->json->expects(self::never())->method('setHttpResponseCode');
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === true));

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testForwardsEmailFirstScopeToVerifier(): void
    {
        $this->enabled();
        $this->payload();
        // The bound account travels with the challenge; the verifier enforces that
        // the asserted credential belongs to it (email-first / passwordless off).
        $this->challengeStorage->method('consume')
            ->willReturn(['challenge' => 'raw-challenge', 'scope' => 42]);

        $source = $this->source('42');
        $this->verifier->expects(self::once())->method('verify')
            ->with('raw-challenge', ['id' => 'abc', 'type' => 'public-key'], 42)
            ->willReturn($source);
        $this->customerRepository->method('getById')->with(42)->willReturn($this->eligibleCustomer());

        $this->json->expects(self::never())->method('setHttpResponseCode');

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testRejectsWhenOwnerBelongsToAnotherWebsite(): void
    {
        $this->enabled();
        $this->payload();
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);
        $this->verifier->method('verify')->willReturn($this->source('42'));
        $this->customerRepository->method('getById')->with(42)->willReturn($this->eligibleCustomer(2));

        $this->session->expects(self::never())->method('setCustomerDataAsLoggedIn');
        $this->logger->expects(self::once())->method('critical');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(422);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testAllowsAnotherWebsiteUnderGlobalAccountSharing(): void
    {
        $this->enabled();
        $this->payload();
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);
        $this->verifier->method('verify')->willReturn($this->source('42'));
        $this->customerRepository->method('getById')->with(42)->willReturn($this->eligibleCustomer(2));
        // Global account sharing: an account signs in on any website, so the
        // owner's website must not gate passkey login (matches native password login).
        $this->shareConfig = $this->createMock(Share::class);
        $this->shareConfig->method('isWebsiteScope')->willReturn(false);
        $controller = $this->controllerWithEligibility();

        $this->session->expects(self::once())->method('setCustomerDataAsLoggedIn');
        $this->json->expects(self::never())->method('setHttpResponseCode');
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === true));

        self::assertSame($this->json, $controller->execute());
    }

    public function testRejectsWhenAccountIsLocked(): void
    {
        $this->enabled();
        $this->payload();
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);
        $this->verifier->method('verify')->willReturn($this->source('42'));
        $this->customerRepository->method('getById')->with(42)->willReturn($this->eligibleCustomer());
        $this->authentication = $this->createMock(AuthenticationInterface::class);
        $this->authentication->method('isLocked')->with(42)->willReturn(true);
        $controller = $this->controllerWithEligibility();

        $this->session->expects(self::never())->method('setCustomerDataAsLoggedIn');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(422);

        self::assertSame($this->json, $controller->execute());
    }

    public function testRejectsWhenAccountIsNotConfirmed(): void
    {
        $this->enabled();
        $this->payload();
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);
        $this->verifier->method('verify')->willReturn($this->source('42'));
        $customer = $this->eligibleCustomer(1, 'pending-key');
        $this->customerRepository->method('getById')->with(42)->willReturn($customer);
        $this->accountConfirmation = $this->createMock(AccountConfirmation::class);
        $this->accountConfirmation->method('isConfirmationRequired')->willReturn(true);
        $controller = $this->controllerWithEligibility();

        $this->session->expects(self::never())->method('setCustomerDataAsLoggedIn');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(422);

        self::assertSame($this->json, $controller->execute());
    }

    public function testRejectsWhenEmailChangeConfirmationPending(): void
    {
        $this->enabled();
        $this->payload();
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);
        $this->verifier->method('verify')->willReturn($this->source('42'));
        $customer = $this->eligibleCustomer(1, 'pending-key');
        $this->customerRepository->method('getById')->with(42)->willReturn($customer);
        // New-account confirmation is off, but a pending email change requires
        // confirmation — native password login rejects this, so passkey must too.
        $this->accountConfirmation = $this->createMock(AccountConfirmation::class);
        $this->accountConfirmation->method('isConfirmationRequired')->willReturn(false);
        $this->accountConfirmation->method('isEmailChangedConfirmationRequired')->willReturn(true);
        $controller = $this->controllerWithEligibility();

        $this->session->expects(self::never())->method('setCustomerDataAsLoggedIn');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(422);

        self::assertSame($this->json, $controller->execute());
    }

    /**
     * A customer for the eligibility gate: on the current website (1 unless
     * overridden), not locked; confirmed unless a confirmation key is supplied.
     *
     * @return CustomerInterface&MockObject
     */
    private function eligibleCustomer(int $websiteId = 1, ?string $confirmation = null): CustomerInterface
    {
        $customer = $this->createMock(CustomerInterface::class);
        $customer->method('getId')->willReturn(42);
        $customer->method('getWebsiteId')->willReturn($websiteId);
        $customer->method('getConfirmation')->willReturn($confirmation);
        $customer->method('getEmail')->willReturn('shopper@acme.test');

        return $customer;
    }

    /**
     * Rebuild the controller after a test swaps an eligibility collaborator mock.
     */
    private function controllerWithEligibility(): Verify
    {
        return new Verify(
            $this->config,
            $this->session,
            $this->request,
            $this->verifier,
            $this->challengeStorage,
            $this->sourceRepository,
            $this->customerRepository,
            $this->jsonFactory(),
            $this->logger,
            $this->rateLimiter,
            $this->storeManager,
            $this->authentication,
            $this->accountConfirmation,
            $this->shareConfig
        );
    }
}
