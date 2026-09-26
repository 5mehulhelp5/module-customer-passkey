<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model;

use DmLab\CustomerPasskey\Model\Credential;
use DmLab\CustomerPasskey\Model\CredentialRepository;
use DmLab\CustomerPasskey\Model\ResourceModel\CredentialResource;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class CredentialRepositoryTest extends TestCase
{
    /** @var CredentialResource&MockObject */
    private $resource;

    /** @var CredentialRepository */
    private CredentialRepository $repository;

    protected function setUp(): void
    {
        $this->resource = $this->createMock(CredentialResource::class);
        $this->repository = new CredentialRepository($this->resource);
    }

    public function testFindByCredentialIdReturnsCredential(): void
    {
        $credential = new Credential(entityId: 7, customerId: 42, credentialId: 'cred-abc');
        $this->resource->expects(self::once())->method('getByCredentialId')
            ->with('cred-abc')->willReturn($credential);

        self::assertSame($credential, $this->repository->findByCredentialId('cred-abc'));
    }

    public function testFindByCredentialIdReturnsNullWhenAbsent(): void
    {
        $this->resource->expects(self::once())->method('getByCredentialId')
            ->with('missing')->willReturn(null);

        self::assertNull($this->repository->findByCredentialId('missing'));
    }

    public function testListByCustomerDelegates(): void
    {
        $credentials = [new Credential(entityId: 7, customerId: 42, credentialId: 'a')];
        $this->resource->expects(self::once())->method('listByCustomer')
            ->with(42)->willReturn($credentials);

        self::assertSame($credentials, $this->repository->listByCustomer(42));
    }

    public function testFindOwnedByCustomerReturnsMatchingRow(): void
    {
        $mine = new Credential(entityId: 7, customerId: 42, credentialId: 'a');
        $other = new Credential(entityId: 8, customerId: 42, credentialId: 'b');
        $this->resource->expects(self::once())->method('listByCustomer')
            ->with(42)->willReturn([$mine, $other]);

        self::assertSame($other, $this->repository->findOwnedByCustomer(42, 8));
    }

    public function testFindOwnedByCustomerReturnsNullWhenNotOwned(): void
    {
        // The row exists, but it belongs to another customer: it is never listed
        // for this customer, so a forged entity_id cannot reach it.
        $this->resource->expects(self::once())->method('listByCustomer')
            ->with(42)->willReturn([new Credential(entityId: 7, customerId: 42, credentialId: 'a')]);

        self::assertNull($this->repository->findOwnedByCustomer(42, 99));
    }

    public function testFindOwnedByCustomerShortCircuitsOnInvalidIds(): void
    {
        $this->resource->expects(self::never())->method('listByCustomer');

        self::assertNull($this->repository->findOwnedByCustomer(0, 7));
        self::assertNull($this->repository->findOwnedByCustomer(42, 0));
    }

    public function testSavePersistsAndReturnsCredential(): void
    {
        $credential = new Credential(customerId: 42, credentialId: 'cred-abc');
        $this->resource->expects(self::once())->method('save')->with($credential);

        self::assertSame($credential, $this->repository->save($credential));
    }

    public function testDeleteDelegates(): void
    {
        $credential = new Credential(entityId: 7, customerId: 42, credentialId: 'cred-abc');
        $this->resource->expects(self::once())->method('delete')->with($credential);

        $this->repository->delete($credential);
    }
}
