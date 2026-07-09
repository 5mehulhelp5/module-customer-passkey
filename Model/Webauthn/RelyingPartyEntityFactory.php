<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Model\Webauthn;

use MageDevGroup\CustomerPasskey\Model\Config;
use Webauthn\PublicKeyCredentialRpEntity;

/**
 * Builds the WebAuthn relying-party entity from module configuration.
 *
 * Magento is the relying party, so the entity's `id` is the base-URL host
 * ({@see Config::getRpId}) and its `name` is the configured display name
 * ({@see Config::getRpDisplayName}). Both the registration and authentication
 * ceremonies feed this into the library's options factories.
 */
class RelyingPartyEntityFactory
{
    /**
     * @param Config $config
     */
    public function __construct(
        private readonly Config $config
    ) {
    }

    /**
     * The relying-party entity for the given store. The `id` is null when the
     * base URL has no resolvable host, letting the library fall back to the
     * effective domain of the request origin.
     *
     * @param int|string|null $storeId
     */
    public function create($storeId = null): PublicKeyCredentialRpEntity
    {
        $rpId = $this->config->getRpId($storeId);

        return PublicKeyCredentialRpEntity::create(
            $this->config->getRpDisplayName($storeId),
            $rpId === '' ? null : $rpId
        );
    }
}
