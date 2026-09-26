<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\ResourceModel;

use DmLab\CustomerPasskey\Model\Credential;
use DmLab\CustomerPasskey\Model\ResourceModel\CredentialResource;
use Magento\Framework\App\ResourceConnection;
use Magento\Framework\DB\Adapter\Pdo\Mysql;
use Magento\Framework\DB\Select;
use Magento\Framework\Serialize\Serializer\Json;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

class CredentialResourceTest extends TestCase
{
    /** @var Mysql&MockObject */
    private $connection;

    /** @var CredentialResource */
    private CredentialResource $resource;

    protected function setUp(): void
    {
        $select = $this->createStub(Select::class);
        foreach (['from', 'where', 'order', 'limit'] as $method) {
            $select->method($method)->willReturnSelf();
        }

        // Concrete adapter: lastInsertId is not on AdapterInterface.
        $this->connection = $this->createMock(Mysql::class);
        $this->connection->method('select')->willReturn($select);

        $resourceConnection = $this->createStub(ResourceConnection::class);
        $resourceConnection->method('getConnection')->willReturn($this->connection);
        $resourceConnection->method('getTableName')->willReturnArgument(0);

        // Real JSON serializer so transports round-trips are asserted end to end.
        $this->resource = new CredentialResource($resourceConnection, new Json());
    }

    /**
     * A representative persisted row.
     *
     * @return array<string,mixed>
     */
    private function row(): array
    {
        return [
            'entity_id' => '7',
            'customer_id' => '42',
            'credential_id' => 'cred-abc',
            'public_key' => 'cG9zZQ==',
            'sign_count' => '5',
            'transports' => '["internal","hybrid"]',
            'aaguid' => 'aa-guid',
            'attestation_type' => 'none',
            'label' => 'My laptop',
            'created_at' => '2026-07-09 10:00:00',
            'last_used_at' => '2026-07-09 12:00:00',
        ];
    }

    public function testGetByCredentialIdMapsRow(): void
    {
        $this->connection->expects(self::once())->method('fetchRow')->willReturn($this->row());

        $credential = $this->resource->getByCredentialId('cred-abc');

        self::assertInstanceOf(Credential::class, $credential);
        self::assertSame(7, $credential->entityId);
        self::assertSame(42, $credential->customerId);
        self::assertSame('cred-abc', $credential->credentialId);
        self::assertSame('cG9zZQ==', $credential->publicKey);
        self::assertSame(5, $credential->signCount);
        self::assertSame(['internal', 'hybrid'], $credential->transports);
        self::assertSame('aa-guid', $credential->aaguid);
        self::assertSame('none', $credential->attestationType);
        self::assertSame('My laptop', $credential->label);
        self::assertSame('2026-07-09 10:00:00', $credential->createdAt);
        self::assertSame('2026-07-09 12:00:00', $credential->lastUsedAt);
    }

    public function testGetByCredentialIdReturnsNullWhenAbsent(): void
    {
        $this->connection->expects(self::once())->method('fetchRow')->willReturn(false);

        self::assertNull($this->resource->getByCredentialId('missing'));
    }

    public function testGetByCredentialIdShortCircuitsOnEmptyId(): void
    {
        $this->connection->expects(self::never())->method('fetchRow');

        self::assertNull($this->resource->getByCredentialId(''));
    }

    public function testGetByCredentialIdTreatsBlankOptionalsAsNull(): void
    {
        $row = $this->row();
        $row['transports'] = '';
        $row['aaguid'] = '';
        $row['label'] = '';
        $row['last_used_at'] = null;
        $this->connection->expects(self::once())->method('fetchRow')->willReturn($row);

        $credential = $this->resource->getByCredentialId('cred-abc');

        self::assertSame([], $credential->transports);
        self::assertNull($credential->aaguid);
        self::assertNull($credential->label);
        self::assertNull($credential->lastUsedAt);
    }

    public function testListByCustomerMapsRows(): void
    {
        $second = $this->row();
        $second['entity_id'] = '8';
        $second['credential_id'] = 'cred-def';
        $this->connection->expects(self::once())->method('fetchAll')->willReturn([$this->row(), $second]);

        $credentials = $this->resource->listByCustomer(42);

        self::assertCount(2, $credentials);
        self::assertSame('cred-abc', $credentials[0]->credentialId);
        self::assertSame('cred-def', $credentials[1]->credentialId);
    }

    public function testListByCustomerShortCircuitsOnInvalidId(): void
    {
        $this->connection->expects(self::never())->method('fetchAll');

        self::assertSame([], $this->resource->listByCustomer(0));
    }

    public function testSaveInsertsWhenEntityIdNull(): void
    {
        $credential = new Credential(
            customerId: 42,
            credentialId: 'cred-abc',
            publicKey: 'cG9zZQ==',
            signCount: 0,
            transports: ['internal'],
            aaguid: 'aa-guid',
            attestationType: 'none',
            label: 'My laptop'
        );

        $captured = null;
        $this->connection->expects(self::once())->method('insert')
            ->willReturnCallback(function ($table, $data) use (&$captured): int {
                $captured = $data;
                return 1;
            });
        $this->connection->method('lastInsertId')->willReturn('7');
        $this->connection->expects(self::never())->method('update');

        $this->resource->save($credential);

        self::assertSame(7, $credential->entityId);
        self::assertSame(42, $captured['customer_id']);
        self::assertSame('cred-abc', $captured['credential_id']);
        self::assertSame('["internal"]', $captured['transports']);
        self::assertArrayNotHasKey('created_at', $captured);
    }

    public function testSaveUpdatesWhenEntityIdPresent(): void
    {
        $credential = new Credential(entityId: 7, customerId: 42, credentialId: 'cred-abc', signCount: 9);

        $captured = null;
        $this->connection->expects(self::never())->method('insert');
        $this->connection->expects(self::once())->method('update')
            ->willReturnCallback(function ($table, $data, $where) use (&$captured): int {
                $captured = ['data' => $data, 'where' => $where];
                return 1;
            });

        $this->resource->save($credential);

        self::assertSame(9, $captured['data']['sign_count']);
        self::assertSame('[]', $captured['data']['transports']);
        self::assertSame(['entity_id = ?' => 7], $captured['where']);
    }

    public function testDeleteRemovesPersistedRow(): void
    {
        $credential = new Credential(entityId: 7, customerId: 42, credentialId: 'cred-abc');

        $this->connection->expects(self::once())->method('delete')
            ->with('dmlab_passkey_credential', ['entity_id = ?' => 7]);

        $this->resource->delete($credential);
    }

    public function testDeleteIsNoopForUnsavedCredential(): void
    {
        $credential = new Credential(customerId: 42, credentialId: 'cred-abc');

        $this->connection->expects(self::never())->method('delete');

        $this->resource->delete($credential);
    }
}
