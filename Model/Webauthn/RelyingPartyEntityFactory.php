<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Webauthn;

use DmLab\CustomerPasskey\Model\Config;
use Webauthn\PublicKeyCredentialRpEntity;

/**
 * Builds the WebAuthn relying-party entity from module configuration.
 *
 * Magento is the relying party, so the entity's `id` is the base-URL host
 * ({@see Config::getRpId}). The library deprecates the entity `name`, so it is left
 * empty here; {@see OptionsSerializer} emits the configured display name as `rp.name`.
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

        return PublicKeyCredentialRpEntity::create('', $rpId === '' ? null : $rpId);
    }
}
