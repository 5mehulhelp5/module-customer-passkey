<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Model\Registration;

use Cose\Algorithms;
use MageDevGroup\CustomerPasskey\Model\Config;
use MageDevGroup\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use MageDevGroup\CustomerPasskey\Model\Webauthn\RelyingPartyEntityFactory;
use Webauthn\AuthenticatorSelectionCriteria;
use Webauthn\PublicKeyCredentialCreationOptions;
use Webauthn\PublicKeyCredentialParameters;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Builds the {@see PublicKeyCredentialCreationOptions} handed to
 * `navigator.credentials.create()` for a logged-in customer.
 *
 * The customer entity is the WebAuthn user (no external IdP): the user handle is
 * the customer id, `name` the email and `displayName` the account name. The
 * customer's already-registered passkeys become `excludeCredentials` so the same
 * authenticator cannot enrol twice. Relying-party, timeout, user-verification and
 * authenticator-attachment come from {@see Config}; resident keys are requested
 * when passwordless (discoverable) login is enabled so the credential can later
 * sign in without an email.
 */
class CreationOptionsFactory
{
    /** Challenge length in bytes (WebAuthn recommends at least 16). */
    private const CHALLENGE_BYTES = 32;

    /**
     * COSE algorithms offered, most preferred first: ES256 then RS256 — the pair
     * mandated by the FIDO2 CTAP profile, covering every mainstream authenticator.
     */
    private const ALGORITHMS = [Algorithms::COSE_ALGORITHM_ES256, Algorithms::COSE_ALGORITHM_RS256];

    /**
     * @param Config $config
     * @param RelyingPartyEntityFactory $relyingPartyEntityFactory
     * @param CredentialSourceRepository $credentialSourceRepository
     */
    public function __construct(
        private readonly Config $config,
        private readonly RelyingPartyEntityFactory $relyingPartyEntityFactory,
        private readonly CredentialSourceRepository $credentialSourceRepository
    ) {
    }

    /**
     * Creation options for the given customer, with a fresh random challenge.
     *
     * @param int $customerId owning customer entity id (the WebAuthn user handle)
     * @param string $username account email shown as the credential's `name`
     * @param string $displayName human-friendly account name
     * @param int|string|null $storeId
     */
    public function create(
        int $customerId,
        string $username,
        string $displayName,
        $storeId = null
    ): PublicKeyCredentialCreationOptions {
        $user = PublicKeyCredentialUserEntity::create($username, (string)$customerId, $displayName);

        return PublicKeyCredentialCreationOptions::create(
            $this->relyingPartyEntityFactory->create($storeId),
            $user,
            random_bytes(self::CHALLENGE_BYTES),
            array_map(
                static fn(int $alg): PublicKeyCredentialParameters => PublicKeyCredentialParameters::createPk($alg),
                self::ALGORITHMS
            ),
            $this->authenticatorSelection($storeId),
            PublicKeyCredentialCreationOptions::ATTESTATION_CONVEYANCE_PREFERENCE_NONE,
            array_map(
                static fn($source) => $source->getPublicKeyCredentialDescriptor(),
                $this->credentialSourceRepository->findAllForUserEntity($user)
            ),
            $this->config->getTimeout($storeId)
        );
    }

    /**
     * Authenticator-selection criteria from config: attachment ({@see Config}'s
     * "any" maps to no preference), user-verification, and a resident-key request
     * only when passwordless login is enabled.
     *
     * @param int|string|null $storeId
     */
    private function authenticatorSelection($storeId): AuthenticatorSelectionCriteria
    {
        $attachment = $this->config->getAuthenticatorAttachment($storeId);

        return AuthenticatorSelectionCriteria::create(
            $attachment === Config::ATTACHMENT_ANY ? null : $attachment,
            $this->config->getUserVerification($storeId),
            $this->config->isPasswordlessAllowed($storeId)
                ? AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_PREFERRED
                : AuthenticatorSelectionCriteria::RESIDENT_KEY_REQUIREMENT_NO_PREFERENCE
        );
    }
}
