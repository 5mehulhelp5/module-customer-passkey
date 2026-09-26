<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Controller\Register;

use DmLab\CustomerPasskey\Controller\Register\Verify;
use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Registration\AttestationVerifier;
use DmLab\CustomerPasskey\Model\Security\RateLimiter;
use DmLab\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use DmLab\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Customer\Model\Session;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
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
            $this->rateLimiter
        );
    }

    private function jsonFactory(): JsonFactory
    {
        $jsonFactory = $this->createStub(JsonFactory::class);
        $jsonFactory->method('create')->willReturn($this->json);

        return $jsonFactory;
    }

    private function loginAs(int $customerId = 42, string $email = 'shopper@acme.test'): void
    {
        $customer = $this->createMock(CustomerInterface::class);
        $customer->method('getEmail')->willReturn($email);
        $customer->method('getFirstname')->willReturn('Jane');
        $customer->method('getLastname')->willReturn('Shopper');

        $this->session->method('isLoggedIn')->willReturn(true);
        $this->session->method('getCustomerId')->willReturn($customerId);
        $this->session->method('getCustomerData')->willReturn($customer);
    }

    private function params(string $payload, string $label = ''): void
    {
        $this->request->method('getParam')->willReturnMap([
            ['publicKeyCredential', '', $payload],
            ['label', '', $label],
        ]);
    }

    private function source(string $rawId = 'raw-cred-id'): PublicKeyCredentialSource
    {
        return PublicKeyCredentialSource::create(
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
            $this->rateLimiter
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
            $limiter
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
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);
        $this->verifier->method('verify')
            ->willThrowException(new \RuntimeException('rpId mismatch.'));

        $this->sourceRepository->expects(self::never())->method('saveNewCredential');
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
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);
        $this->verifier->method('verify')->willReturn($this->source());

        $this->sourceRepository->expects(self::once())->method('findOneByCredentialId')
            ->with('raw-cred-id')->willReturn($this->source());
        $this->sourceRepository->expects(self::never())->method('saveNewCredential');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(409);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testStoresValidAttestationWithLabel(): void
    {
        $this->loginAs();
        $this->params('{"id":"abc","type":"public-key"}', ' My laptop ');
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);

        $source = $this->source();
        $this->verifier->expects(self::once())->method('verify')
            ->with(42, 'shopper@acme.test', 'Jane Shopper', 'raw-challenge', ['id' => 'abc', 'type' => 'public-key'])
            ->willReturn($source);
        $this->sourceRepository->method('findOneByCredentialId')->willReturn(null);

        $this->sourceRepository->expects(self::once())->method('saveNewCredential')
            ->with($source, 'My laptop');
        $this->json->expects(self::never())->method('setHttpResponseCode');
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === true));

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testStoresValidAttestationWithoutLabel(): void
    {
        $this->loginAs();
        $this->params('{"id":"abc","type":"public-key"}');
        $this->challengeStorage->method('consume')->willReturn(['challenge' => 'raw-challenge', 'scope' => null]);
        $this->verifier->method('verify')->willReturn($this->source());
        $this->sourceRepository->method('findOneByCredentialId')->willReturn(null);

        $this->sourceRepository->expects(self::once())->method('saveNewCredential')
            ->with(self::isInstanceOf(PublicKeyCredentialSource::class), null);

        self::assertSame($this->json, $this->controller->execute());
    }
}
