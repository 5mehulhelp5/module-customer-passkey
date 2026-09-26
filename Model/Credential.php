<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model;

/**
 * A registered passkey (WebAuthn credential) for a storefront customer — see
 * etc/db_schema.xml. A plain mutable data holder: persistence lives in
 * {@see \DmLab\CustomerPasskey\Model\ResourceModel\CredentialResource} and
 * the API surface in {@see CredentialRepository}. `entityId` is null until the row
 * is persisted. The library ↔ storage type mapping (COSE key, transports) is wired
 * in a later task; here the fields are transport-agnostic strings.
 */
class Credential
{
    /**
     * @param int|null $entityId credential row id (null before persistence)
     * @param int $customerId owning customer entity id
     * @param string $credentialId base64url of the WebAuthn credential id
     * @param string $publicKey base64 of the COSE public key
     * @param int $signCount last seen authenticator signature counter
     * @param string[] $transports authenticator transports (e.g. internal, hybrid)
     * @param string|null $aaguid authenticator AAGUID
     * @param string|null $attestationType attestation statement type
     * @param string|null $label customer-friendly label
     * @param string|null $createdAt registration time (set by the DB default)
     * @param string|null $lastUsedAt last successful assertion time
     */
    public function __construct(
        public ?int $entityId = null,
        public int $customerId = 0,
        public string $credentialId = '',
        public string $publicKey = '',
        public int $signCount = 0,
        public array $transports = [],
        public ?string $aaguid = null,
        public ?string $attestationType = null,
        public ?string $label = null,
        public ?string $createdAt = null,
        public ?string $lastUsedAt = null
    ) {
    }
}
