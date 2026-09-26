<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\ResourceModel;

use DmLab\CustomerPasskey\Model\Credential;
use Magento\Framework\App\ResourceConnection;
use Magento\Framework\Serialize\Serializer\Json;

/**
 * Persistence for the `dmlab_passkey_credential` table.
 *
 * Direct-connection CRUD over a credential row, translating rows to/from the
 * {@see Credential} DTO (transports are stored as a JSON array). Lookups are by
 * the unique `credential_id` (assertion time) and by `customer_id` (My Account /
 * registration `excludeCredentials`).
 */
class CredentialResource
{
    private const TABLE = 'dmlab_passkey_credential';

    /**
     * @param ResourceConnection $resource
     * @param Json $json
     */
    public function __construct(
        private readonly ResourceConnection $resource,
        private readonly Json $json
    ) {
    }

    /**
     * Load the credential with the given base64url id, or null when absent.
     *
     * @param string $credentialId
     */
    public function getByCredentialId(string $credentialId): ?Credential
    {
        if ($credentialId === '') {
            return null;
        }

        $connection = $this->resource->getConnection();
        $select = $connection->select()
            ->from($this->table())
            ->where('credential_id = ?', $credentialId)
            ->limit(1);

        $row = $connection->fetchRow($select);

        return is_array($row) && $row !== [] ? $this->toCredential($row) : null;
    }

    /**
     * All credentials owned by a customer, oldest first.
     *
     * @param int $customerId
     * @return Credential[]
     */
    public function listByCustomer(int $customerId): array
    {
        if ($customerId <= 0) {
            return [];
        }

        $connection = $this->resource->getConnection();
        $select = $connection->select()
            ->from($this->table())
            ->where('customer_id = ?', $customerId)
            ->order('entity_id ASC');

        return array_map([$this, 'toCredential'], $connection->fetchAll($select));
    }

    /**
     * Persist a credential (insert when `entityId` is null, else update).
     *
     * On insert `entityId` is populated from the new row; `created_at` is left to
     * the DB default and never rewritten.
     *
     * @param Credential $credential
     */
    public function save(Credential $credential): void
    {
        $connection = $this->resource->getConnection();
        $data = [
            'customer_id' => $credential->customerId,
            'credential_id' => $credential->credentialId,
            'public_key' => $credential->publicKey,
            'sign_count' => $credential->signCount,
            'transports' => $this->json->serialize(array_values($credential->transports)),
            'aaguid' => $credential->aaguid,
            'attestation_type' => $credential->attestationType,
            'label' => $credential->label,
            'last_used_at' => $credential->lastUsedAt,
        ];

        if ($credential->entityId === null) {
            $connection->insert($this->table(), $data);
            $credential->entityId = (int)$connection->lastInsertId($this->table());

            return;
        }

        $connection->update($this->table(), $data, ['entity_id = ?' => $credential->entityId]);
    }

    /**
     * Delete a persisted credential row. A no-op for an unsaved credential.
     *
     * @param Credential $credential
     */
    public function delete(Credential $credential): void
    {
        if ($credential->entityId === null) {
            return;
        }

        $connection = $this->resource->getConnection();
        $connection->delete($this->table(), ['entity_id = ?' => $credential->entityId]);
    }

    /**
     * Map a table row to a {@see Credential}.
     *
     * @param array<string,mixed> $row
     */
    private function toCredential(array $row): Credential
    {
        $transports = [];
        if (isset($row['transports']) && $row['transports'] !== '') {
            $decoded = $this->json->unserialize((string)$row['transports']);
            $transports = is_array($decoded) ? array_values(array_map('strval', $decoded)) : [];
        }

        return new Credential(
            entityId: isset($row['entity_id']) ? (int)$row['entity_id'] : null,
            customerId: (int)($row['customer_id'] ?? 0),
            credentialId: (string)($row['credential_id'] ?? ''),
            publicKey: (string)($row['public_key'] ?? ''),
            signCount: (int)($row['sign_count'] ?? 0),
            transports: $transports,
            aaguid: $this->nullableString($row['aaguid'] ?? null),
            attestationType: $this->nullableString($row['attestation_type'] ?? null),
            label: $this->nullableString($row['label'] ?? null),
            createdAt: $this->nullableString($row['created_at'] ?? null),
            lastUsedAt: $this->nullableString($row['last_used_at'] ?? null)
        );
    }

    /**
     * A trimmed non-empty string, or null.
     *
     * @param mixed $value
     */
    private function nullableString(mixed $value): ?string
    {
        return $value === null || $value === '' ? null : (string)$value;
    }

    /**
     * Resolved (prefixed) table name.
     */
    private function table(): string
    {
        return $this->resource->getTableName(self::TABLE);
    }
}
