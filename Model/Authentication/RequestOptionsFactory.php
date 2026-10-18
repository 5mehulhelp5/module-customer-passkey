<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Authentication;

use DmLab\CustomerPasskey\Model\Config;
use Webauthn\PublicKeyCredentialRequestOptions;

/**
 * Builds the {@see PublicKeyCredentialRequestOptions} handed to
 * `navigator.credentials.get()` for a passwordless storefront login.
 *
 * Login is discoverable-only: `allowCredentials` is always empty, so the
 * authenticator offers any resident key for this relying party and the response
 * never reveals whether an account exists or which credential ids it holds.
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
     */
    public function __construct(
        private readonly Config $config
    ) {
    }

    /**
     * Request options with a fresh random challenge.
     *
     * @param int|string|null $storeId
     */
    public function create($storeId = null): PublicKeyCredentialRequestOptions
    {
        $rpId = $this->config->getRpId($storeId);

        return PublicKeyCredentialRequestOptions::create(
            random_bytes(self::CHALLENGE_BYTES),
            $rpId === '' ? null : $rpId,
            [],
            $this->config->getUserVerification($storeId),
            $this->config->getTimeout($storeId)
        );
    }
}
