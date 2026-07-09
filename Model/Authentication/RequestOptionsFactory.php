<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Model\Authentication;

use MageDevGroup\CustomerPasskey\Model\Config;
use MageDevGroup\CustomerPasskey\Model\Webauthn\CredentialSourceRepository;
use Webauthn\PublicKeyCredentialRequestOptions;
use Webauthn\PublicKeyCredentialUserEntity;

/**
 * Builds the {@see PublicKeyCredentialRequestOptions} handed to
 * `navigator.credentials.get()` for a passwordless storefront login.
 *
 * Two modes, selected by the caller:
 *  - usernameless/discoverable — no customer id, so `allowCredentials` is empty and
 *    the authenticator offers any resident key for this relying party;
 *  - email-first — the resolved customer's registered passkeys become
 *    `allowCredentials`, so the browser prompts for one of that account's keys.
 *
 * Relying-party id, user-verification and timeout come from {@see Config}; every
 * call gets a fresh random challenge the caller persists for the verify step.
 */
class RequestOptionsFactory
{
    /** Challenge length in bytes (WebAuthn recommends at least 16). */
    private const CHALLENGE_BYTES = 32;

    /**
     * @param Config $config
     * @param CredentialSourceRepository $credentialSourceRepository
     */
    public function __construct(
        private readonly Config $config,
        private readonly CredentialSourceRepository $credentialSourceRepository
    ) {
    }

    /**
     * Request options with a fresh random challenge.
     *
     * @param int|null $customerId email-first target customer, or null for discoverable
     * @param int|string|null $storeId
     */
    public function create(?int $customerId = null, $storeId = null): PublicKeyCredentialRequestOptions
    {
        $rpId = $this->config->getRpId($storeId);

        return PublicKeyCredentialRequestOptions::create(
            random_bytes(self::CHALLENGE_BYTES),
            $rpId === '' ? null : $rpId,
            $this->allowCredentials($customerId),
            $this->config->getUserVerification($storeId),
            $this->config->getTimeout($storeId)
        );
    }

    /**
     * The customer's registered passkeys as credential descriptors.
     *
     * Empty for discoverable login (no customer) or a customer with no passkeys.
     *
     * @param int|null $customerId
     * @return \Webauthn\PublicKeyCredentialDescriptor[]
     */
    private function allowCredentials(?int $customerId): array
    {
        if ($customerId === null || $customerId <= 0) {
            return [];
        }

        $user = PublicKeyCredentialUserEntity::create('', (string)$customerId, '');

        return array_map(
            static fn($source) => $source->getPublicKeyCredentialDescriptor(),
            $this->credentialSourceRepository->findAllForUserEntity($user)
        );
    }
}
