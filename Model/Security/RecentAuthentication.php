<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Security;

use DmLab\CustomerPasskey\Model\Config;
use Magento\Customer\Model\AuthenticationInterface;
use Magento\Customer\Model\Session;
use Magento\Framework\Exception\InvalidEmailOrPasswordException;
use Magento\Framework\Exception\NoSuchEntityException;
use Magento\Framework\Exception\State\UserLockedException;
use Magento\Framework\Stdlib\DateTime\DateTime;
use Psr\Log\LoggerInterface;

/**
 * Tracks when the customer last proved who they are (sign-in or password
 * confirmation), so adding a passkey can demand a fresh proof — a hijacked
 * session alone must not be able to enrol an attacker's authenticator.
 */
class RecentAuthentication
{
    /** Customer-session key holding the unix timestamp of the last proof. */
    private const SESSION_KEY = 'dmlab_customer_passkey_auth_at';

    /** Set by Magento_LoginAsCustomer on an admin impersonation session. */
    private const IMPERSONATION_KEY = 'logged_as_customer_admind_id';

    /**
     * @param Session $session
     * @param AuthenticationInterface $authentication
     * @param Config $config
     * @param DateTime $dateTime
     * @param LoggerInterface $logger
     */
    public function __construct(
        private readonly Session $session,
        private readonly AuthenticationInterface $authentication,
        private readonly Config $config,
        private readonly DateTime $dateTime,
        private readonly LoggerInterface $logger
    ) {
    }

    /**
     * Record that the customer has just authenticated.
     */
    public function markNow(): void
    {
        $this->session->setData(self::SESSION_KEY, $this->dateTime->gmtTimestamp());
    }

    /**
     * Whether the last proof is within the configured re-authentication window.
     *
     * Never for "Login as Customer": the admin's sign-in is no proof of the customer.
     */
    public function isFresh(): bool
    {
        if ((int)$this->session->getData(self::IMPERSONATION_KEY) > 0) {
            return false;
        }

        $authenticatedAt = (int)$this->session->getData(self::SESSION_KEY);
        if ($authenticatedAt <= 0) {
            return false;
        }

        return $this->dateTime->gmtTimestamp() - $authenticatedAt <= $this->config->getReauthWindow();
    }

    /**
     * Verify the customer's password.
     *
     * Failures count toward the native lockout; a locked account is refused even
     * with the correct password.
     *
     * @param int $customerId
     * @param string $password
     */
    public function confirmPassword(int $customerId, string $password): bool
    {
        try {
            if ($this->authentication->isLocked($customerId)) {
                $this->logger->info(sprintf('Passkey re-authentication refused for locked customer %d', $customerId));

                return false;
            }

            return (bool)$this->authentication->authenticate($customerId, $password);
        } catch (InvalidEmailOrPasswordException | UserLockedException | NoSuchEntityException $e) {
            $this->logger->info(
                sprintf('Passkey re-authentication failed for customer %d: %s', $customerId, $e->getMessage())
            );

            return false;
        }
    }
}
