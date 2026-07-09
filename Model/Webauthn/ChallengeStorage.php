<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Model\Webauthn;

use Magento\Customer\Model\Session;

/**
 * One-time store for the WebAuthn ceremony challenge in the storefront session.
 *
 * The options controllers {@see save} the freshly generated challenge before
 * returning the creation/request options; the verify controllers {@see consume}
 * it exactly once. Consuming clears the slot, so a replayed attestation/assertion
 * finds no challenge and is rejected. The raw challenge (binary) is base64-encoded
 * for safe session serialization.
 *
 * A login-options request also binds the account it scoped the request to (the
 * email-first customer, or 0 for an unknown email); the login verify enforces the
 * asserted credential belongs to that account. The scope travels in the same slot
 * as the challenge so the two can never desynchronise. Registration leaves it null.
 */
class ChallengeStorage
{
    /** Session key holding the pending ceremony state (challenge + login scope). */
    private const SESSION_KEY = 'magedevgroup_customer_passkey_challenge';

    /**
     * @param Session $session
     */
    public function __construct(
        private readonly Session $session
    ) {
    }

    /**
     * Store the raw challenge and optional login scope, replacing any pending one.
     *
     * @param string $challenge raw challenge bytes
     * @param int|null $scopeCustomerId email-first account the request was scoped to
     *                 (0 = unknown email; null = discoverable / registration)
     */
    public function save(string $challenge, ?int $scopeCustomerId = null): void
    {
        $this->session->setData(self::SESSION_KEY, (string)json_encode([
            'c' => base64_encode($challenge),
            's' => $scopeCustomerId,
        ]));
    }

    /**
     * Return and clear the pending ceremony state, or null when none is pending.
     *
     * A second call returns null — the challenge is single-use.
     *
     * @return array{challenge: string, scope: int|null}|null
     */
    public function consume(): ?array
    {
        $stored = $this->session->getData(self::SESSION_KEY);
        if (!is_string($stored) || $stored === '') {
            return null;
        }

        $this->session->unsetData(self::SESSION_KEY);

        $decoded = json_decode($stored, true);
        if (!is_array($decoded) || !isset($decoded['c']) || !is_string($decoded['c'])) {
            return null;
        }

        $scope = $decoded['s'] ?? null;

        return [
            'challenge' => (string)base64_decode($decoded['c'], true),
            'scope' => $scope === null ? null : (int)$scope,
        ];
    }
}
