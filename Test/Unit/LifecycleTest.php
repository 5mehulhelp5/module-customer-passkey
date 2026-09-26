<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit;

use DmLab\CustomerPasskey\Controller\Login\Verify as LoginVerify;
use DmLab\CustomerPasskey\Controller\Manage\Delete;
use DmLab\CustomerPasskey\Controller\Register\Verify as RegisterVerify;
use DmLab\CustomerPasskey\Model\Authentication\AssertionVerifier;
use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Credential;
use DmLab\CustomerPasskey\Model\CredentialRepository;
use DmLab\CustomerPasskey\Model\Registration\AttestationVerifier;
use DmLab\CustomerPasskey\Model\Security\RateLimiter;
use DmLab\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use DmLab\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Customer\Model\AccountConfirmation;
use Magento\Customer\Model\AuthenticationInterface;
use Magento\Customer\Model\Config\Share;
use Magento\Customer\Model\Session;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use Magento\Framework\Stdlib\DateTime\DateTime;
use Magento\Store\Api\Data\StoreInterface;
use Magento\Store\Model\StoreManagerInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Full passkey lifecycle over the real controllers and storage adapter, with the
 * cryptographic ceremony (attestation/assertion) stubbed: a customer registers a
 * credential, later signs in passwordlessly with it (the advanced sign counter is
 * persisted), then deletes it. Exercises the register → login → delete seam end to
 * end against an in-memory credential store.
 */
#[AllowMockObjectsWithoutExpectations]
class LifecycleTest extends TestCase
{
    private const NIL_AAGUID = '00000000-0000-0000-0000-000000000000';
    private const CUSTOMER_ID = 42;
    private const RAW_CREDENTIAL_ID = 'raw-cred-id';
    private const LOGIN_TIME = '2026-07-09 12:00:00';

    /** @var CredentialRepository in-memory credential store shared across the flow */
    private CredentialRepository $store;

    /** @var CredentialSourceRepository real library adapter over {@see $store} */
    private CredentialSourceRepository $sourceRepository;

    protected function setUp(): void
    {
        $this->store = new class extends CredentialRepository {
            /** @var array<int,Credential> */
            private array $rows = [];

            /** @var int next synthetic row id */
            private int $nextId = 1;

            // Test double: bypass the parent constructor; state lives in $rows.
            public function __construct()
            {
            }

            public function findByCredentialId(string $credentialId): ?Credential
            {
                foreach ($this->rows as $row) {
                    if ($row->credentialId === $credentialId) {
                        return $row;
                    }
                }

                return null;
            }

            public function listByCustomer(int $customerId): array
            {
                return array_values(
                    array_filter($this->rows, static fn(Credential $c): bool => $c->customerId === $customerId)
                );
            }

            public function findOwnedByCustomer(int $customerId, int $entityId): ?Credential
            {
                $row = $this->rows[$entityId] ?? null;

                return $row !== null && $row->customerId === $customerId ? $row : null;
            }

            public function save(Credential $credential): Credential
            {
                if ($credential->entityId === null) {
                    $credential->entityId = $this->nextId++;
                }
                $this->rows[$credential->entityId] = $credential;

                return $credential;
            }

            public function delete(Credential $credential): void
            {
                if ($credential->entityId !== null) {
                    unset($this->rows[$credential->entityId]);
                }
            }

            public function count(): int
            {
                return count($this->rows);
            }
        };

        $dateTime = $this->createStub(DateTime::class);
        $dateTime->method('gmtDate')->willReturn(self::LOGIN_TIME);
        $this->sourceRepository = new CredentialSourceRepository($this->store, $dateTime);
    }

    private function source(int $counter): PublicKeyCredentialSource
    {
        return PublicKeyCredentialSource::create(
            self::RAW_CREDENTIAL_ID,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString(self::NIL_AAGUID),
            'raw-cose-key',
            (string)self::CUSTOMER_ID,
            $counter
        );
    }

    private function json(): Json
    {
        $json = $this->createMock(Json::class);
        $json->method('setHttpResponseCode')->willReturnSelf();
        $json->method('setData')->willReturnSelf();

        return $json;
    }

    private function jsonFactory(Json $json): JsonFactory
    {
        $factory = $this->createStub(JsonFactory::class);
        $factory->method('create')->willReturn($json);

        return $factory;
    }

    private function allowingLimiter(): RateLimiter
    {
        $limiter = $this->createMock(RateLimiter::class);
        $limiter->method('registerAttempt')->willReturn(true);

        return $limiter;
    }

    public function testRegisterLoginDeleteLifecycle(): void
    {
        // 1) Register: the attestation verifier is stubbed; the controller persists
        //    the resulting source through the real storage adapter.
        $customer = $this->createMock(CustomerInterface::class);
        $customer->method('getEmail')->willReturn('shopper@acme.test');
        $customer->method('getFirstname')->willReturn('Jane');
        $customer->method('getLastname')->willReturn('Shopper');
        // Eligibility inputs for the login step: current website, confirmed.
        $customer->method('getId')->willReturn(self::CUSTOMER_ID);
        $customer->method('getWebsiteId')->willReturn(1);
        $customer->method('getConfirmation')->willReturn(null);

        $registerSession = $this->createMock(Session::class);
        $registerSession->method('isLoggedIn')->willReturn(true);
        $registerSession->method('getCustomerId')->willReturn(self::CUSTOMER_ID);
        $registerSession->method('getCustomerData')->willReturn($customer);

        $registerRequest = $this->createMock(RequestInterface::class);
        $registerRequest->method('getParam')->willReturnMap([
            ['publicKeyCredential', '', '{"id":"abc","type":"public-key"}'],
            ['label', '', 'My laptop'],
        ]);

        $attestation = $this->createMock(AttestationVerifier::class);
        $attestation->method('verify')->willReturn($this->source(0));

        $registerChallenge = $this->createMock(ChallengeStorage::class);
        $registerChallenge->method('consume')->willReturn(['challenge' => 'reg-challenge', 'scope' => null]);

        $registerConfig = $this->createMock(Config::class);
        $registerConfig->method('isEnabled')->willReturn(true);

        $registerJson = $this->json();
        $register = new RegisterVerify(
            $registerConfig,
            $registerSession,
            $registerRequest,
            $attestation,
            $registerChallenge,
            $this->sourceRepository,
            $this->jsonFactory($registerJson),
            $this->createMock(LoggerInterface::class),
            $this->allowingLimiter()
        );

        $registerJson->expects(self::never())->method('setHttpResponseCode');
        $register->execute();

        self::assertSame(1, $this->store->count(), 'Registration stores exactly one credential.');
        $stored = $this->store->listByCustomer(self::CUSTOMER_ID)[0];
        self::assertSame('My laptop', $stored->label);
        self::assertSame(0, $stored->signCount);
        $entityId = $stored->entityId;

        // 2) Passwordless login: the assertion verifier is stubbed to return the same
        //    credential with an advanced counter; the controller must persist it.
        $loginSession = $this->createMock(Session::class);
        $loginRequest = $this->createMock(RequestInterface::class);
        $loginRequest->method('getParam')->willReturnMap([
            ['publicKeyCredential', '', '{"id":"abc","type":"public-key"}'],
        ]);

        $config = $this->createMock(Config::class);
        $config->method('isEnabled')->willReturn(true);

        $assertion = $this->createMock(AssertionVerifier::class);
        $assertion->method('verify')->willReturn($this->source(5));

        $loginChallenge = $this->createMock(ChallengeStorage::class);
        $loginChallenge->method('consume')->willReturn(['challenge' => 'login-challenge', 'scope' => null]);

        $customerRepository = $this->createMock(CustomerRepositoryInterface::class);
        $customerRepository->expects(self::once())->method('getById')->with(self::CUSTOMER_ID)
            ->willReturn($customer);

        $store = $this->createStub(StoreInterface::class);
        $store->method('getWebsiteId')->willReturn(1);
        $storeManager = $this->createStub(StoreManagerInterface::class);
        $storeManager->method('getStore')->willReturn($store);
        $authentication = $this->createStub(AuthenticationInterface::class);
        $authentication->method('isLocked')->willReturn(false);
        $accountConfirmation = $this->createStub(AccountConfirmation::class);
        $accountConfirmation->method('isConfirmationRequired')->willReturn(false);
        $shareConfig = $this->createStub(Share::class);
        $shareConfig->method('isWebsiteScope')->willReturn(true);

        $loginJson = $this->json();
        $login = new LoginVerify(
            $config,
            $loginSession,
            $loginRequest,
            $assertion,
            $loginChallenge,
            $this->sourceRepository,
            $customerRepository,
            $this->jsonFactory($loginJson),
            $this->createMock(LoggerInterface::class),
            $this->allowingLimiter(),
            $storeManager,
            $authentication,
            $accountConfirmation,
            $shareConfig
        );

        $loginSession->expects(self::once())->method('setCustomerDataAsLoggedIn')->with($customer);
        $loginJson->expects(self::never())->method('setHttpResponseCode');
        $login->execute();

        self::assertSame(1, $this->store->count(), 'Login updates the credential in place.');
        self::assertSame(
            5,
            $this->store->listByCustomer(self::CUSTOMER_ID)[0]->signCount,
            'The advanced sign counter is persisted for clone detection.'
        );
        self::assertSame(
            self::LOGIN_TIME,
            $this->store->listByCustomer(self::CUSTOMER_ID)[0]->lastUsedAt,
            'Login stamps the last-used time for the My Account listing.'
        );

        // 3) Delete: the customer removes the passkey; the store is left empty.
        $deleteSession = $this->createMock(Session::class);
        $deleteSession->method('isLoggedIn')->willReturn(true);
        $deleteSession->method('getCustomerId')->willReturn(self::CUSTOMER_ID);

        $deleteRequest = $this->createMock(RequestInterface::class);
        $deleteRequest->method('getParam')->with('entity_id', 0)->willReturn($entityId);

        $deleteJson = $this->json();
        $delete = new Delete(
            $deleteSession,
            $deleteRequest,
            $this->store,
            $this->jsonFactory($deleteJson)
        );

        $deleteJson->expects(self::never())->method('setHttpResponseCode');
        $delete->execute();

        self::assertSame(0, $this->store->count(), 'Deletion removes the credential.');
    }
}
