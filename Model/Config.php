<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Store\Model\ScopeInterface;
use Magento\Store\Model\StoreManagerInterface;

/**
 * Typed reader over the module's storefront configuration.
 *
 * Wraps {@see ScopeConfigInterface} so the rest of the module never touches raw
 * config paths, and derives the WebAuthn relying-party id from the store base
 * URL (Magento is the relying party — there is no admin field for it). Reads are
 * store-scoped: passkey login can be enabled/tuned per store view.
 */
class Config
{
    /** Whether passkey login is enabled. */
    public const XML_PATH_ENABLED = 'magedevgroup_customer_passkey/general/enabled';

    /** Human-readable relying-party name shown by the authenticator. */
    public const XML_PATH_RP_DISPLAY_NAME = 'magedevgroup_customer_passkey/general/rp_display_name';

    /** WebAuthn user-verification requirement (required/preferred/discouraged). */
    public const XML_PATH_USER_VERIFICATION = 'magedevgroup_customer_passkey/general/user_verification';

    /** Authenticator attachment preference (any/platform/cross-platform). */
    public const XML_PATH_AUTHENTICATOR_ATTACHMENT = 'magedevgroup_customer_passkey/general/authenticator_attachment';

    /** Ceremony timeout in milliseconds. */
    public const XML_PATH_TIMEOUT = 'magedevgroup_customer_passkey/general/timeout';

    /** Whether usernameless/discoverable ("Sign in with a passkey") login is offered. */
    public const XML_PATH_ALLOW_PASSWORDLESS = 'magedevgroup_customer_passkey/general/allow_passwordless';

    /** The user must prove presence + verification (PIN/biometric). */
    public const USER_VERIFICATION_REQUIRED = 'required';

    /** Verification is requested but not enforced (safe default). */
    public const USER_VERIFICATION_PREFERRED = 'preferred';

    /** Verification is discouraged (presence only). */
    public const USER_VERIFICATION_DISCOURAGED = 'discouraged';

    /** No attachment restriction — omit the criterion from the ceremony. */
    public const ATTACHMENT_ANY = 'any';

    /** Built-in platform authenticator (Touch ID, Windows Hello). */
    public const ATTACHMENT_PLATFORM = 'platform';

    /** Roaming authenticator (hardware security key). */
    public const ATTACHMENT_CROSS_PLATFORM = 'cross-platform';

    /** Ceremony timeout used when the admin leaves the field blank. */
    public const DEFAULT_TIMEOUT = 60000;

    /**
     * @param ScopeConfigInterface $scopeConfig
     * @param StoreManagerInterface $storeManager
     */
    public function __construct(
        private readonly ScopeConfigInterface $scopeConfig,
        private readonly StoreManagerInterface $storeManager
    ) {
    }

    /**
     * Whether passkey login is enabled for the given store.
     *
     * @param int|string|null $storeId
     */
    public function isEnabled($storeId = null): bool
    {
        return $this->scopeConfig->isSetFlag(
            self::XML_PATH_ENABLED,
            ScopeInterface::SCOPE_STORE,
            $storeId
        );
    }

    /**
     * Relying-party display name; falls back to the store frontend name.
     *
     * @param int|string|null $storeId
     */
    public function getRpDisplayName($storeId = null): string
    {
        $value = $this->readNonEmptyString(self::XML_PATH_RP_DISPLAY_NAME, $storeId);
        if ($value !== null) {
            return $value;
        }

        $fallback = $this->scopeConfig->getValue(
            'general/store_information/name',
            ScopeInterface::SCOPE_STORE,
            $storeId
        );

        return is_string($fallback) && trim($fallback) !== '' ? trim($fallback) : 'Magento';
    }

    /**
     * Configured user-verification requirement.
     *
     * Falls back to the safe {@see self::USER_VERIFICATION_PREFERRED} when unset
     * or unrecognized.
     *
     * @param int|string|null $storeId
     */
    public function getUserVerification($storeId = null): string
    {
        $value = $this->readNonEmptyString(self::XML_PATH_USER_VERIFICATION, $storeId);

        return in_array($value, [
            self::USER_VERIFICATION_REQUIRED,
            self::USER_VERIFICATION_PREFERRED,
            self::USER_VERIFICATION_DISCOURAGED,
        ], true) ? $value : self::USER_VERIFICATION_PREFERRED;
    }

    /**
     * Configured authenticator attachment.
     *
     * {@see self::ATTACHMENT_ANY} (no restriction) when unset or unrecognized.
     *
     * @param int|string|null $storeId
     */
    public function getAuthenticatorAttachment($storeId = null): string
    {
        $value = $this->readNonEmptyString(self::XML_PATH_AUTHENTICATOR_ATTACHMENT, $storeId);

        return in_array($value, [
            self::ATTACHMENT_PLATFORM,
            self::ATTACHMENT_CROSS_PLATFORM,
        ], true) ? $value : self::ATTACHMENT_ANY;
    }

    /**
     * Ceremony timeout in milliseconds; {@see self::DEFAULT_TIMEOUT} when unset
     * or non-positive.
     *
     * @param int|string|null $storeId
     */
    public function getTimeout($storeId = null): int
    {
        $value = (int)$this->scopeConfig->getValue(
            self::XML_PATH_TIMEOUT,
            ScopeInterface::SCOPE_STORE,
            $storeId
        );

        return $value > 0 ? $value : self::DEFAULT_TIMEOUT;
    }

    /**
     * Whether usernameless/discoverable login is offered.
     *
     * @param int|string|null $storeId
     */
    public function isPasswordlessAllowed($storeId = null): bool
    {
        return $this->scopeConfig->isSetFlag(
            self::XML_PATH_ALLOW_PASSWORDLESS,
            ScopeInterface::SCOPE_STORE,
            $storeId
        );
    }

    /**
     * The WebAuthn relying-party id: the host of the store base URL, stripped of
     * scheme, port and path (e.g. `https://shop.example.com/` → `shop.example.com`).
     * Empty string when the base URL has no resolvable host.
     *
     * @param int|string|null $storeId
     */
    public function getRpId($storeId = null): string
    {
        $baseUrl = $this->storeManager->getStore($storeId)->getBaseUrl();
        $host = parse_url($baseUrl, PHP_URL_HOST);

        return is_string($host) ? $host : '';
    }

    /**
     * Read a store-scoped config value as a trimmed non-empty string, or null.
     *
     * @param string $path
     * @param int|string|null $storeId
     */
    private function readNonEmptyString(string $path, $storeId = null): ?string
    {
        $value = $this->scopeConfig->getValue($path, ScopeInterface::SCOPE_STORE, $storeId);
        $value = is_string($value) ? trim($value) : '';

        return $value === '' ? null : $value;
    }
}
