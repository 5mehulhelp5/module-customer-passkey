<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Model\Webauthn;

use MageDevGroup\CustomerPasskey\Model\Credential;
use MageDevGroup\CustomerPasskey\Model\CredentialRepository;
use Magento\Framework\Stdlib\DateTime\DateTime;
use Symfony\Component\Uid\Uuid;
use Webauthn\PublicKeyCredentialDescriptor;
use Webauthn\PublicKeyCredentialSource;
use Webauthn\PublicKeyCredentialSourceRepository;
use Webauthn\PublicKeyCredentialUserEntity;
use Webauthn\TrustPath\EmptyTrustPath;

/**
 * Adapts our credential storage ({@see CredentialRepository}) to the library's
 * {@see PublicKeyCredentialSourceRepository} contract so the attestation and
 * assertion validators read and write credentials through our table.
 *
 * Type mapping between the two worlds:
 *  - the library uses raw binary ids/keys; we persist the credential id as
 *    base64url and the COSE public key as base64;
 *  - the WebAuthn user handle is the owning customer id (there is no external
 *    IdP, so the customer entity is the user);
 *  - the AAGUID is a {@see Uuid}; the all-zero (nil) AAGUID is stored as null.
 *
 * The interface is deprecated upstream but remains the supported v4 seam for the
 * classic ceremony validators this module uses.
 */
class CredentialSourceRepository implements PublicKeyCredentialSourceRepository
{
    /** AAGUID emitted by authenticators that withhold one; stored as null. */
    private const NIL_AAGUID = '00000000-0000-0000-0000-000000000000';

    /**
     * @param CredentialRepository $credentials
     * @param DateTime $dateTime
     */
    public function __construct(
        private readonly CredentialRepository $credentials,
        private readonly DateTime $dateTime
    ) {
    }

    /**
     * @inheritDoc
     */
    public function findOneByCredentialId(string $publicKeyCredentialId): ?PublicKeyCredentialSource
    {
        $credential = $this->credentials->findByCredentialId($this->encodeBase64Url($publicKeyCredentialId));

        return $credential === null ? null : $this->toSource($credential);
    }

    /**
     * @inheritDoc
     */
    public function findAllForUserEntity(PublicKeyCredentialUserEntity $publicKeyCredentialUserEntity): array
    {
        $customerId = (int)$publicKeyCredentialUserEntity->id;
        if ($customerId <= 0) {
            return [];
        }

        return array_map(
            fn(Credential $credential): PublicKeyCredentialSource => $this->toSource($credential),
            $this->credentials->listByCustomer($customerId)
        );
    }

    /**
     * @inheritDoc
     */
    public function saveCredentialSource(PublicKeyCredentialSource $publicKeyCredentialSource): void
    {
        $credentialId = $this->encodeBase64Url($publicKeyCredentialSource->publicKeyCredentialId);
        $existing = $this->credentials->findByCredentialId($credentialId);

        $credential = $this->toCredential($publicKeyCredentialSource, $existing);
        // This is the assertion (login) write path; stamp the last successful use.
        $credential->lastUsedAt = $this->dateTime->gmtDate();

        $this->credentials->save($credential);
    }

    /**
     * Persist a freshly attested credential, applying the optional enrol-time label.
     *
     * The library write path ({@see saveCredentialSource}) is label-agnostic; this
     * is the registration entry point, so it records the customer-chosen label on
     * the new row. The credential id is expected to be unused (the caller rejects
     * duplicates first), so a new row is always created.
     *
     * @param PublicKeyCredentialSource $source
     * @param string|null $label
     */
    public function saveNewCredential(PublicKeyCredentialSource $source, ?string $label = null): Credential
    {
        $credential = $this->toCredential($source, null);
        if ($label !== null && $label !== '') {
            $credential->label = $label;
        }

        return $this->credentials->save($credential);
    }

    /**
     * Map a stored credential to the library source used by the validators.
     *
     * @param Credential $credential
     */
    private function toSource(Credential $credential): PublicKeyCredentialSource
    {
        $aaguid = $credential->aaguid !== null && Uuid::isValid($credential->aaguid)
            ? Uuid::fromString($credential->aaguid)
            : Uuid::fromString(self::NIL_AAGUID);

        return PublicKeyCredentialSource::create(
            $this->decodeBase64Url($credential->credentialId),
            PublicKeyCredentialDescriptor::CREDENTIAL_TYPE_PUBLIC_KEY,
            $credential->transports,
            $credential->attestationType ?? 'none',
            EmptyTrustPath::create(),
            $aaguid,
            $this->decodeBase64($credential->publicKey),
            (string)$credential->customerId,
            $credential->signCount
        );
    }

    /**
     * Merge a library source into a (possibly existing) stored credential.
     *
     * On an existing row the owning customer, label and creation time are kept;
     * the counter and mutable attestation fields are refreshed. A new row takes
     * the customer id from the source's user handle.
     *
     * @param PublicKeyCredentialSource $source
     * @param Credential|null $existing
     */
    private function toCredential(PublicKeyCredentialSource $source, ?Credential $existing): Credential
    {
        $credential = $existing ?? new Credential(customerId: (int)$source->userHandle);

        $credential->credentialId = $this->encodeBase64Url($source->publicKeyCredentialId);
        $credential->publicKey = $this->encodeBase64($source->credentialPublicKey);
        $credential->signCount = $source->counter;
        $credential->transports = $source->transports;
        $credential->attestationType = $source->attestationType;

        $aaguid = $source->aaguid->toRfc4122();
        $credential->aaguid = $aaguid === self::NIL_AAGUID ? null : $aaguid;

        return $credential;
    }

    /**
     * Encode raw bytes as unpadded base64url (our stored credential-id form).
     *
     * @param string $raw
     */
    private function encodeBase64Url(string $raw): string
    {
        return rtrim(strtr(base64_encode($raw), '+/', '-_'), '=');
    }

    /**
     * Decode an unpadded base64url string back to raw bytes.
     *
     * @param string $value
     */
    private function decodeBase64Url(string $value): string
    {
        return (string)base64_decode(strtr($value, '-_', '+/'), true);
    }

    /**
     * Encode raw COSE key bytes as base64 (our stored public-key form).
     *
     * @param string $raw
     */
    private function encodeBase64(string $raw): string
    {
        return base64_encode($raw);
    }

    /**
     * Decode a base64 string back to raw bytes.
     *
     * @param string $value
     */
    private function decodeBase64(string $value): string
    {
        return (string)base64_decode($value, true);
    }
}
