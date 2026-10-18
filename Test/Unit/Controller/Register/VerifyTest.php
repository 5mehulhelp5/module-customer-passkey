<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Controller\Register;

use DmLab\CustomerPasskey\Controller\Register\Verify;
use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Notification\PasskeyNotifier;
use DmLab\CustomerPasskey\Model\Registration\AttestationVerifier;
use DmLab\CustomerPasskey\Model\Security\RateLimiter;
use DmLab\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use DmLab\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Customer\Model\Session;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use Magento\Framework\TestFramework\Unit\Helper\MockCreationTrait;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;
use Symfony\Component\Uid\Uuid;
use Webauthn\CredentialRecord;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\TrustPath\EmptyTrustPath;

#[AllowMockObjectsWithoutExpectations]
class VerifyTest extends TestCase
{
    use MockCreationTrait;

    private const NIL_AAGUID = '00000000-0000-0000-0000-000000000000';

    /** @var Config&MockObject */
    private $config;

    /** @var Session&MockObject */
    private $session;

    /** @var RequestInterface&MockObject */
    private $request;

    /** @var AttestationVerifier&MockObject */
    private $verifier;

    /** @var ChallengeStorage&MockObject */
    private $challengeStorage;

    /** @var CredentialSourceRepository&MockObject */
    private $sourceRepository;

    /** @var Json&MockObject */
    private $json;

    /** @var LoggerInterface&MockObject */
    private $logger;

    /** @var RateLimiter&MockObject */
    private $rateLimiter;

    /** @var PasskeyNotifier&MockObject */
    private $notifier;

    /** @var Verify */
    private Verify $controller;

    protected function setUp(): void
    {
        $this->config = $this->createMock(Config::class);
        $this->config->method('isEnabled')->willReturn(true);
        $this->session = $this->createMock(Session::class);
        $this->request = $this->createMock(RequestInterface::class);
        $this->verifier = $this->createMock(AttestationVerifier::class);
        $this->challengeStorage = $this->createMock(ChallengeStorage::class);
        $this->sourceRepository = $this->createMock(CredentialSourceRepository::class);
        $this->logger = $this->createMock(LoggerInterface::class);
        $this->rateLimiter = $this->createMock(RateLimiter::class);
        $this->rateLimiter->method('registerAttempt')->willReturn(true);
        $this->notifier = $this->createMock(PasskeyNotifier::class);

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
            $jsonFactory,
            $this->logger,
            $this->rateLimiter,
            $this->notifier
        );
    }

    private function jsonFactory(): JsonFactory
    {
        $jsonFactory = $this->createStub(JsonFactory::class);
        $jsonFactory->method('create')->willReturn($this->json);

        return $jsonFactory;
    }

    private function loginAs(int $customerId = 42, string $email = 'shopper@acme.test'): CustomerInterface
    {
        $customer = $this->createMock(CustomerInterface::class);
        $customer->method('getEmail')->willReturn($email);
        $customer->method('getFirstname')->willReturn('Jane');
        $customer->method('getLastname')->willReturn('Shopper');

        $this->session->method('isLoggedIn')->willReturn(true);
        $this->session->method('getCustomerId')->willReturn($customerId);
        $this->session->method('getCustomerData')->willReturn($customer);

        return $customer;
    }

    private function params(string $payload, string $label = ''): void
    {
        $this->request->method('getParam')->willReturnMap([
            ['publicKeyCredential', '', $payload],
            ['label', '', $label],
        ]);
    }

    private function source(string $rawId = 'raw-cred-id'): CredentialRecord
    {
        return CredentialRecord::create(
            $rawId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString(self::NIL_AAGUID),
            'raw-cose-key',
            '42',
            0
        );
    }

    public function testRefusesWhenDisabled(): void
    {
        $config = $this->createMock(Config::class);
        $config->method('isEnabled')->willReturn(false);
        $controller = new Verify(
            $config,
            $this->session,
            $this->request,
            $this->verifier,
            $this->challengeStorage,
            $this->sourceRepository,
            $this->jsonFactory(),
            $this->logger,
            $this->rateLimiter,
            $this->notifier
        );

        $this->session->expects(self::never())->method('isLoggedIn');
        $this->verifier->expects(self::never())->method('verify');
        $this->sourceRepository->expects(self::never())->method('saveNewCredential');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(403);

        self::assertSame($this->json, $controller->execute());
    }

    public function testRefusesAnonymousRequest(): void
    {
        $this->session->method('isLoggedIn')->willReturn(false);

        $this->challengeStorage->expects(self::never())->method('consume');
        $this->verifier->expects(self::never())->method('verify');
        $this->sourceRepository->expects(self::never())->method('saveNewCredential');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(403);
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === false));

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testThrottlesAfterTooManyAttempts(): void
    {
        $this->loginAs();

        $limiter = $this->createMock(RateLimiter::class);
        $limiter->method('registerAttempt')->willReturn(false);
        $controller = new Verify(
            $this->config,
            $this->session,
            $this->request,
            $this->verifier,
            $this->challengeStorage,
            $this->sourceRepository,
            $this->jsonFactory(),
            $this->logger,
            $limiter,
            $this->notifier
        );

        $this->challengeStorage->expects(self::never())->method('consume');
        $this->verifier->expects(self::never())->method('verify');
        $this->sourceRepository->expects(self::never())->method('saveNewCredential');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(429);

        self::assertSame($this->json, $controller->execute());
    }

    public function testRejectsMalformedPayloadBeforeConsumingChallenge(): void
    {
        $this->loginAs();
        $this->params('not-json');

        $this->challengeStorage->expects(self::never())->method('consume');
        $this->verifier->expects(self::never())->method('verify');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(400);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testRejectsMissingChallenge(): void
    {
        $this->loginAs();
        $this->params('{"id":"abc","type":"public-key"}');
        $this->challengeStorage->method('consume')->willReturn(null);

        $this->verifier->expects(self::never())->method('verify');
        $this->sourceRepository->expects(self::never())->method('saveNewCredential');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(400);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testRejectsInvalidAttestation(): void
    {
        $this->loginAs();
        $this->params('{"id":"abc","type":"public-key"}');
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => 42]);
        $this->verifier->method('verify')
            ->willThrowException(new \RuntimeException('rpId mismatch.'));

        $this->sourceRepository->expects(self::never())->method('saveNewCredential');
        $this->notifier->expects(self::never())->method('notifyAdded');
        $this->logger->expects(self::once())->method('critical');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(422);
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === false));

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testRejectsDuplicateCredential(): void
    {
        $this->loginAs();
        $this->params('{"id":"abc","type":"public-key"}');
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => 42]);
        $this->verifier->method('verify')->willReturn($this->source());

        $this->sourceRepository->expects(self::once())->method('findOneByCredentialId')
            ->with('raw-cred-id')->willReturn($this->source());
        $this->sourceRepository->expects(self::never())->method('saveNewCredential');
        $this->notifier->expects(self::never())->method('notifyAdded');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(409);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testStoresValidAttestationWithLabel(): void
    {
        $customer = $this->loginAs();
        $this->params('{"id":"abc","type":"public-key"}', ' My laptop ');
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => 42]);

        $source = $this->source();
        $this->verifier->expects(self::once())->method('verify')
            ->with(42, 'shopper@acme.test', 'Jane Shopper', 'raw-challenge', ['id' => 'abc', 'type' => 'public-key'])
            ->willReturn($source);
        $this->sourceRepository->method('findOneByCredentialId')->willReturn(null);

        $this->sourceRepository->expects(self::once())->method('saveNewCredential')
            ->with($source, 'My laptop');
        $this->notifier->expects(self::once())->method('notifyAdded')
            ->with($customer, 'My laptop');
        $this->json->expects(self::never())->method('setHttpResponseCode');
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === true));

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testStoresValidAttestationWithoutLabel(): void
    {
        $this->loginAs();
        $this->params('{"id":"abc","type":"public-key"}');
        $this->challengeStorage->expects(self::once())->method('consume')
            ->with(ChallengeStorage::CEREMONY_REGISTER)
            ->willReturn(['challenge' => 'raw-challenge', 'scope' => 42]);
        $this->verifier->method('verify')->willReturn($this->source());
        $this->sourceRepository->method('findOneByCredentialId')->willReturn(null);

        $this->sourceRepository->expects(self::once())->method('saveNewCredential')
            ->with(self::isInstanceOf(CredentialRecord::class), null);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testRejectsLoginMintedChallenge(): void
    {
        $this->loginAs();
        $this->params('{"id":"abc","type":"public-key"}');
        $storage = $this->sessionBackedChallengeStorage();
        // A logged-in session can mint a login challenge; it must not complete a registration.
        $storage->save(ChallengeStorage::CEREMONY_LOGIN, 'login-challenge');

        $this->verifier->expects(self::never())->method('verify');
        $this->sourceRepository->expects(self::never())->method('saveNewCredential');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(400);

        self::assertSame($this->json, $this->controllerWith($storage)->execute());
        self::assertNull($storage->consume(ChallengeStorage::CEREMONY_LOGIN));
    }

    public function testAcceptsRegisterMintedChallenge(): void
    {
        $this->loginAs();
        $this->params('{"id":"abc","type":"public-key"}');
        $storage = $this->sessionBackedChallengeStorage();
        $storage->save(ChallengeStorage::CEREMONY_REGISTER, 'register-challenge', 42);
        $this->sourceRepository->method('findOneByCredentialId')->willReturn(null);

        $this->verifier->expects(self::once())->method('verify')
            ->with(42, 'shopper@acme.test', self::anything(), 'register-challenge', self::anything())
            ->willReturn($this->source());
        $this->sourceRepository->expects(self::once())->method('saveNewCredential');
        $this->json->expects(self::never())->method('setHttpResponseCode');

        self::assertSame($this->json, $this->controllerWith($storage)->execute());
    }

    public function testRejectsChallengeIssuedToAnotherCustomer(): void
    {
        $this->loginAs(42);
        $this->params('{"id":"abc","type":"public-key"}');
        $storage = $this->sessionBackedChallengeStorage();
        // Minted for customer 7, then the session switched (e.g. Login as Customer).
        $storage->save(ChallengeStorage::CEREMONY_REGISTER, 'register-challenge', 7);

        $this->verifier->expects(self::never())->method('verify');
        $this->sourceRepository->expects(self::never())->method('saveNewCredential');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(400);

        self::assertSame($this->json, $this->controllerWith($storage)->execute());
        self::assertNull($storage->consume(ChallengeStorage::CEREMONY_REGISTER));
    }

    public function testRejectsUnboundRegisterChallenge(): void
    {
        $this->loginAs(42);
        $this->params('{"id":"abc","type":"public-key"}');
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);

        $this->verifier->expects(self::never())->method('verify');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(400);

        self::assertSame($this->json, $this->controller->execute());
    }

    private function controllerWith(ChallengeStorage $storage): Verify
    {
        return new Verify(
            $this->config,
            $this->session,
            $this->request,
            $this->verifier,
            $storage,
            $this->sourceRepository,
            $this->jsonFactory(),
            $this->logger,
            $this->rateLimiter,
            $this->notifier
        );
    }

    /**
     * A real ChallengeStorage over an in-memory customer-session slot.
     */
    private function sessionBackedChallengeStorage(): ChallengeStorage
    {
        $slot = [];
        $session = $this->createPartialMockWithReflection(Session::class, ['getData', 'setData', 'unsetData']);
        $session->method('getData')->willReturnCallback(static function ($key) use (&$slot) {
            return $slot[$key] ?? null;
        });
        $session->method('setData')->willReturnCallback(static function ($key, $value) use (&$slot): void {
            $slot[$key] = $value;
        });
        $session->method('unsetData')->willReturnCallback(static function ($key) use (&$slot): void {
            unset($slot[$key]);
        });

        return new ChallengeStorage($session);
    }
}
