<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model;

use DmLab\CustomerPasskey\Model\ResourceModel\CredentialResource;

/**
 * The application-facing store for passkey credentials: resolve a credential by
 * its base64url id (assertion), list a customer's credentials (My Account /
 * registration `excludeCredentials`), and save/delete. Thin guards over
 * {@see CredentialResource}; the ceremony and library-type mapping live in later
 * tasks and consume this repository rather than the resource directly.
 */
class CredentialRepository
{
    /**
     * @param CredentialResource $resource
     */
    public function __construct(
        private readonly CredentialResource $resource
    ) {
    }

    /**
     * The credential registered under the given base64url id, or null when unknown.
     *
     * @param string $credentialId
     */
    public function findByCredentialId(string $credentialId): ?Credential
    {
        return $this->resource->getByCredentialId($credentialId);
    }

    /**
     * All passkeys owned by a customer, oldest first (empty for an invalid id).
     *
     * @param int $customerId
     * @return Credential[]
     */
    public function listByCustomer(int $customerId): array
    {
        return $this->resource->listByCustomer($customerId);
    }

    /**
     * The customer's own credential with the given row id, or null when it is not
     * theirs (or unknown). The ownership seam for My Account rename/delete: a
     * credential is resolved only within the requesting customer's own set, so a
     * forged `entity_id` for another shopper's passkey can never be reached.
     *
     * @param int $customerId
     * @param int $entityId
     */
    public function findOwnedByCustomer(int $customerId, int $entityId): ?Credential
    {
        if ($customerId <= 0 || $entityId <= 0) {
            return null;
        }

        foreach ($this->resource->listByCustomer($customerId) as $credential) {
            if ($credential->entityId === $entityId) {
                return $credential;
            }
        }

        return null;
    }

    /**
     * Persist a credential (insert or update), returning it with `entityId` set.
     *
     * @param Credential $credential
     */
    public function save(Credential $credential): Credential
    {
        $this->resource->save($credential);

        return $credential;
    }

    /**
     * Remove a credential. A no-op for one that was never persisted.
     *
     * @param Credential $credential
     */
    public function delete(Credential $credential): void
    {
        $this->resource->delete($credential);
    }
}
