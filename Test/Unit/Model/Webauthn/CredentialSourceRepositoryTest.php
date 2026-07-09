<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Test\Unit\Model\Webauthn;

use MageDevGroup\CustomerPasskey\Model\Credential;
use MageDevGroup\CustomerPasskey\Model\CredentialRepository;
use MageDevGroup\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use Magento\Framework\Stdlib\DateTime\DateTime;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

#[AllowMockObjectsWithoutExpectations]
class CredentialSourceRepositoryTest extends TestCase
{
    private const AAGUID = 'f8a011f3-8c0a-4d15-8006-17111f9edc7d';
    private const NIL_AAGUID = '00000000-0000-0000-0000-000000000000';

    private const NOW = '2026-07-09 12:00:00';

    /** @var CredentialRepository&MockObject */
    private $credentials;

    /** @var CredentialSourceRepository */
    private CredentialSourceRepository $repository;

    protected function setUp(): void
    {
        $this->credentials = $this->createMock(CredentialRepository::class);
        $dateTime = $this->createStub(DateTime::class);
        $dateTime->method('gmtDate')->willReturn(self::NOW);
        $this->repository = new CredentialSourceRepository($this->credentials, $dateTime);
    }

    private function encodeBase64Url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    public function testFindOneMapsStoredCredentialToSource(): void
    {
        $credential = new Credential(
            entityId: 3,
            customerId: 42,
            credentialId: $this->encodeBase64Url('raw-credential-id'),
            publicKey: base64_encode('raw-cose-key'),
            signCount: 5,
            transports: ['internal', 'hybrid'],
            aaguid: self::AAGUID,
            attestationType: 'packed'
        );
        $this->credentials->expects(self::once())->method('findByCredentialId')
            ->with($this->encodeBase64Url('raw-credential-id'))->willReturn($credential);

        $source = $this->repository->findOneByCredentialId('raw-credential-id');

        self::assertInstanceOf(PublicKeyCredentialSource::class, $source);
        self::assertSame('raw-credential-id', $source->publicKeyCredentialId);
        self::assertSame(PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY, $source->type);
        self::assertSame('raw-cose-key', $source->credentialPublicKey);
        self::assertSame(5, $source->counter);
        self::assertSame('42', $source->userHandle);
        self::assertSame(['internal', 'hybrid'], $source->transports);
        self::assertSame('packed', $source->attestationType);
        self::assertSame(self::AAGUID, $source->aaguid->toRfc4122());
    }

    public function testFindOneReturnsNullWhenAbsent(): void
    {
        $this->credentials->expects(self::once())->method('findByCredentialId')
            ->with($this->encodeBase64Url('missing'))->willReturn(null);

        self::assertNull($this->repository->findOneByCredentialId('missing'));
    }

    public function testFindOneMapsNullAaguidToNil(): void
    {
        $credential = new Credential(
            customerId: 1,
            credentialId: $this->encodeBase64Url('c'),
            publicKey: base64_encode('k'),
            aaguid: null
        );
        $this->credentials->method('findByCredentialId')->willReturn($credential);

        $source = $this->repository->findOneByCredentialId('c');

        self::assertSame(self::NIL_AAGUID, $source->aaguid->toRfc4122());
    }

    public function testFindAllForUserEntityMapsEachCredential(): void
    {
        $user = PublicKeyCredentialUserEntity::create('john@example.com', '42', 'John');
        $credentials = [
            new Credential(customerId: 42, credentialId: $this->encodeBase64Url('a'), publicKey: base64_encode('ka')),
            new Credential(customerId: 42, credentialId: $this->encodeBase64Url('b'), publicKey: base64_encode('kb')),
        ];
        $this->credentials->expects(self::once())->method('listByCustomer')
            ->with(42)->willReturn($credentials);

        $sources = $this->repository->findAllForUserEntity($user);

        self::assertCount(2, $sources);
        self::assertSame('a', $sources[0]->publicKeyCredentialId);
        self::assertSame('b', $sources[1]->publicKeyCredentialId);
    }

    public function testFindAllForInvalidUserHandleReturnsEmpty(): void
    {
        $user = PublicKeyCredentialUserEntity::create('guest', 'not-a-number', 'Guest');
        $this->credentials->expects(self::never())->method('listByCustomer');

        self::assertSame([], $this->repository->findAllForUserEntity($user));
    }

    public function testSaveNewCredentialTakesCustomerFromUserHandle(): void
    {
        $source = $this->source('new-cred', 'new-key', userHandle: '77', counter: 0, aaguid: self::NIL_AAGUID);
        $this->credentials->method('findByCredentialId')->willReturn(null);

        $saved = null;
        $this->credentials->expects(self::once())->method('save')
            ->willReturnCallback(function (Credential $c) use (&$saved): Credential {
                $saved = $c;
                return $c;
            });

        $this->repository->saveCredentialSource($source);

        self::assertNull($saved->entityId);
        self::assertSame(77, $saved->customerId);
        self::assertSame($this->encodeBase64Url('new-cred'), $saved->credentialId);
        self::assertSame(base64_encode('new-key'), $saved->publicKey);
        self::assertSame(0, $saved->signCount);
        self::assertNull($saved->aaguid);
        self::assertSame('none', $saved->attestationType);
    }

    public function testSaveExistingCredentialPreservesOwnershipAndUpdatesCounter(): void
    {
        $existing = new Credential(
            entityId: 9,
            customerId: 42,
            credentialId: $this->encodeBase64Url('known'),
            publicKey: base64_encode('key'),
            signCount: 3,
            label: 'My laptop',
            createdAt: '2026-01-01 00:00:00'
        );
        $this->credentials->method('findByCredentialId')
            ->with($this->encodeBase64Url('known'))->willReturn($existing);

        $source = $this->source('known', 'key', userHandle: '999', counter: 10, aaguid: self::AAGUID);

        $saved = null;
        $this->credentials->expects(self::once())->method('save')
            ->willReturnCallback(function (Credential $c) use (&$saved): Credential {
                $saved = $c;
                return $c;
            });

        $this->repository->saveCredentialSource($source);

        self::assertSame(9, $saved->entityId);
        // Ownership is not reassigned from the assertion's user handle.
        self::assertSame(42, $saved->customerId);
        self::assertSame('My laptop', $saved->label);
        self::assertSame('2026-01-01 00:00:00', $saved->createdAt);
        self::assertSame(10, $saved->signCount);
        self::assertSame(self::AAGUID, $saved->aaguid);
        self::assertSame(self::NOW, $saved->lastUsedAt, 'Login stamps the last-used time.');
    }

    public function testFindOneMapsInvalidStoredAaguidToNil(): void
    {
        $credential = new Credential(
            customerId: 1,
            credentialId: $this->encodeBase64Url('c'),
            publicKey: base64_encode('k'),
            aaguid: 'not-a-uuid'
        );
        $this->credentials->method('findByCredentialId')->willReturn($credential);

        $source = $this->repository->findOneByCredentialId('c');

        self::assertSame(self::NIL_AAGUID, $source->aaguid->toRfc4122());
    }

    public function testSaveCredentialSourceStampsLastUsedOnNewRow(): void
    {
        $source = $this->source('login-cred', 'login-key', userHandle: '77', counter: 1, aaguid: self::NIL_AAGUID);
        $this->credentials->method('findByCredentialId')->willReturn(null);

        $saved = null;
        $this->credentials->expects(self::once())->method('save')
            ->willReturnCallback(function (Credential $c) use (&$saved): Credential {
                $saved = $c;
                return $c;
            });

        $this->repository->saveCredentialSource($source);

        self::assertSame(self::NOW, $saved->lastUsedAt);
    }

    public function testSaveNewCredentialAppliesLabelToNewRow(): void
    {
        $source = $this->source('fresh', 'fresh-key', userHandle: '55', counter: 0, aaguid: self::AAGUID);

        $saved = null;
        $this->credentials->expects(self::once())->method('save')
            ->willReturnCallback(function (Credential $c) use (&$saved): Credential {
                $saved = $c;
                return $c;
            });

        $this->repository->saveNewCredential($source, 'Work key');

        self::assertNull($saved->entityId);
        self::assertSame(55, $saved->customerId);
        self::assertSame($this->encodeBase64Url('fresh'), $saved->credentialId);
        self::assertSame('Work key', $saved->label);
        self::assertSame(self::AAGUID, $saved->aaguid);
    }

    public function testSaveNewCredentialLeavesLabelNullWhenNotProvided(): void
    {
        $source = $this->source('fresh', 'fresh-key', userHandle: '55', counter: 0, aaguid: self::NIL_AAGUID);

        $saved = null;
        $this->credentials->expects(self::once())->method('save')
            ->willReturnCallback(function (Credential $c) use (&$saved): Credential {
                $saved = $c;
                return $c;
            });

        $this->repository->saveNewCredential($source, null);

        self::assertNull($saved->label);
    }

    private function source(
        string $rawId,
        string $rawKey,
        string $userHandle,
        int $counter,
        string $aaguid
    ): PublicKeyCredentialSource {
        return PublicKeyCredentialSource::create(
            $rawId,
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            [],
            'none',
            EmptyTrustPath::create(),
            Uuid::fromString($aaguid),
            $rawKey,
            $userHandle,
            $counter
        );
    }
}
