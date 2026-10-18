<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Webauthn;

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
 * as the challenge so the two can never desynchronise. Registration binds the
 * customer it was issued to; the register verify rejects any other customer.
 *
 * The slot is bound to the ceremony that minted it: consuming it for another
 * ceremony (e.g. a login-minted challenge sent to register/verify) clears it and
 * yields null, so one ceremony's gate cannot be bypassed via the other.
 */
class ChallengeStorage
{
    public const CEREMONY_LOGIN = 'login';
    public const CEREMONY_REGISTER = 'register';

    /** Session key holding the pending ceremony state (challenge + login scope + ceremony). */
    private const SESSION_KEY = 'dmlab_customer_passkey_challenge';

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
     * @param string $ceremony self::CEREMONY_LOGIN or self::CEREMONY_REGISTER
     * @param string $challenge raw challenge bytes
     * @param int|null $scopeCustomerId login: email-first account (0 = unknown email,
     *                 null = discoverable); registration: the issuing customer
     */
    public function save(string $ceremony, string $challenge, ?int $scopeCustomerId = null): void
    {
        $this->session->setData(self::SESSION_KEY, (string)json_encode([
            'c' => base64_encode($challenge),
            's' => $scopeCustomerId,
            't' => $ceremony,
        ]));
    }

    /**
     * Return and clear the pending ceremony state, or null when none is pending.
     *
     * A second call returns null — the challenge is single-use. A slot minted for
     * another ceremony (or without one, from a pre-upgrade session) is cleared too
     * and yields null.
     *
     * @param string $ceremony self::CEREMONY_LOGIN or self::CEREMONY_REGISTER
     * @return array{challenge: string, scope: int|null}|null
     */
    public function consume(string $ceremony): ?array
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

        if (($decoded['t'] ?? null) !== $ceremony) {
            return null;
        }

        $scope = $decoded['s'] ?? null;

        return [
            'challenge' => (string)base64_decode($decoded['c'], true),
            'scope' => $scope === null ? null : (int)$scope,
        ];
    }
}
