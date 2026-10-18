<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model;

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
    public const XML_PATH_ENABLED = 'dmlab_customer_passkey/general/enabled';

    /** Human-readable relying-party name shown by the authenticator. */
    public const XML_PATH_RP_DISPLAY_NAME = 'dmlab_customer_passkey/general/rp_display_name';

    /** WebAuthn user-verification requirement (required/preferred/discouraged). */
    public const XML_PATH_USER_VERIFICATION = 'dmlab_customer_passkey/general/user_verification';

    /** Authenticator attachment preference (any/platform/cross-platform). */
    public const XML_PATH_AUTHENTICATOR_ATTACHMENT = 'dmlab_customer_passkey/general/authenticator_attachment';

    /** Ceremony timeout in milliseconds. */
    public const XML_PATH_TIMEOUT = 'dmlab_customer_passkey/general/timeout';

    /** Whether usernameless/discoverable ("Sign in with a passkey") login is offered. */
    public const XML_PATH_ALLOW_PASSWORDLESS = 'dmlab_customer_passkey/general/allow_passwordless';

    /** Seconds a sign-in or password confirmation stays fresh enough to add a passkey. */
    public const XML_PATH_REAUTH_WINDOW = 'dmlab_customer_passkey/general/reauth_window';

    /** Whether passkey added/removed emails are sent. */
    public const XML_PATH_NOTIFICATION_ENABLED = 'dmlab_customer_passkey/notification/enabled';

    /** Sender identity for passkey notifications (e.g. `general`). */
    public const XML_PATH_NOTIFICATION_IDENTITY = 'dmlab_customer_passkey/notification/identity';

    /** Email template sent when a passkey is added. */
    public const XML_PATH_NOTIFICATION_ADDED_TEMPLATE = 'dmlab_customer_passkey/notification/added_template';

    /** Email template sent when a passkey is removed. */
    public const XML_PATH_NOTIFICATION_REMOVED_TEMPLATE = 'dmlab_customer_passkey/notification/removed_template';

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

    /** Re-authentication window used when the admin leaves the field blank. */
    public const DEFAULT_REAUTH_WINDOW = 300;

    /** Bundled "passkey added" template id (etc/email_templates.xml). */
    public const DEFAULT_ADDED_TEMPLATE = 'dmlab_customer_passkey_notification_added_template';

    /** Bundled "passkey removed" template id (etc/email_templates.xml). */
    public const DEFAULT_REMOVED_TEMPLATE = 'dmlab_customer_passkey_notification_removed_template';

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
     * Ceremony timeout in milliseconds; {@see self::DEFAULT_TIMEOUT} when unset or non-positive.
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
     * Re-authentication window in seconds.
     *
     * {@see self::DEFAULT_REAUTH_WINDOW} when unset or non-positive.
     *
     * @param int|string|null $storeId
     */
    public function getReauthWindow($storeId = null): int
    {
        $value = (int)$this->scopeConfig->getValue(
            self::XML_PATH_REAUTH_WINDOW,
            ScopeInterface::SCOPE_STORE,
            $storeId
        );

        return $value > 0 ? $value : self::DEFAULT_REAUTH_WINDOW;
    }

    /**
     * Whether passkey added/removed notifications are sent.
     *
     * @param int|string|null $storeId
     */
    public function isNotificationEnabled($storeId = null): bool
    {
        return $this->scopeConfig->isSetFlag(
            self::XML_PATH_NOTIFICATION_ENABLED,
            ScopeInterface::SCOPE_STORE,
            $storeId
        );
    }

    /**
     * Sender identity for notifications; `general` when unset.
     *
     * @param int|string|null $storeId
     */
    public function getNotificationIdentity($storeId = null): string
    {
        return $this->readNonEmptyString(self::XML_PATH_NOTIFICATION_IDENTITY, $storeId) ?? 'general';
    }

    /**
     * Template id for the "passkey added" email; the bundled one when unset.
     *
     * @param int|string|null $storeId
     */
    public function getAddedTemplate($storeId = null): string
    {
        return $this->readNonEmptyString(self::XML_PATH_NOTIFICATION_ADDED_TEMPLATE, $storeId)
            ?? self::DEFAULT_ADDED_TEMPLATE;
    }

    /**
     * Template id for the "passkey removed" email; the bundled one when unset.
     *
     * @param int|string|null $storeId
     */
    public function getRemovedTemplate($storeId = null): string
    {
        return $this->readNonEmptyString(self::XML_PATH_NOTIFICATION_REMOVED_TEMPLATE, $storeId)
            ?? self::DEFAULT_REMOVED_TEMPLATE;
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
