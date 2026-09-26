<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Security;

use Magento\Framework\App\CacheInterface;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;

/**
 * Per-client throttle for the WebAuthn ceremony endpoints.
 *
 * Each caller (identified by remote address) gets at most {@see registerAttempt}'s
 * `$maxAttempts` hits per `$windowSeconds` against a named bucket; the count lives
 * in the shared cache with the window as its TTL, so an idle window expires and the
 * budget refills. Keyed per bucket + client so registration and login throttle
 * independently and one shopper's activity never blocks another's.
 *
 * This caps brute-forcing an assertion and abusive options/challenge generation;
 * the cryptographic checks (challenge, origin/RP-ID, signature, counter) remain the
 * primary defence — this only bounds the request rate.
 */
class RateLimiter
{
    /** Cache tag so all passkey throttle counters can be flushed together. */
    private const CACHE_TAG = 'DMLAB_CUSTOMER_PASSKEY_RL';

    /** Cache-key prefix for a throttle counter. */
    private const KEY_PREFIX = 'dmlab_customer_passkey_rl_';

    /**
     * @param CacheInterface $cache
     * @param RemoteAddress $remoteAddress
     */
    public function __construct(
        private readonly CacheInterface $cache,
        private readonly RemoteAddress $remoteAddress
    ) {
    }

    /**
     * Record an attempt against the bucket and report whether it is within budget.
     *
     * Returns true while the client is at or under `$maxAttempts` for the window and
     * false once the limit is exceeded; a rejected attempt does not extend the
     * window, so the budget refills `$windowSeconds` after the last accepted hit.
     *
     * @param string $bucket logical action, e.g. `login_verify`
     * @param int $maxAttempts attempts allowed per window
     * @param int $windowSeconds rolling window length in seconds
     */
    public function registerAttempt(string $bucket, int $maxAttempts, int $windowSeconds): bool
    {
        $key = $this->key($bucket);
        $count = (int)$this->cache->load($key);

        if ($count >= $maxAttempts) {
            return false;
        }

        $this->cache->save((string)($count + 1), $key, [self::CACHE_TAG], $windowSeconds);

        return true;
    }

    /**
     * Cache key for the bucket, scoped to the (hashed) client address.
     *
     * @param string $bucket
     */
    private function key(string $bucket): string
    {
        $client = $this->remoteAddress->getRemoteAddress();
        $client = is_string($client) && $client !== '' ? $client : 'unknown';

        return self::KEY_PREFIX . $bucket . '_' . hash('sha256', $client);
    }
}
