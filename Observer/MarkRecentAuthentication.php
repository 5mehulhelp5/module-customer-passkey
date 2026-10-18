<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Observer;

use DmLab\CustomerPasskey\Model\Security\RecentAuthentication;
use Magento\Framework\Event\Observer;
use Magento\Framework\Event\ObserverInterface;

/**
 * Marks the session freshly authenticated on every storefront sign-in
 * (password, SSO or passkey — all dispatch `customer_login`).
 */
class MarkRecentAuthentication implements ObserverInterface
{
    /**
     * @param RecentAuthentication $recentAuthentication
     */
    public function __construct(
        private readonly RecentAuthentication $recentAuthentication
    ) {
    }

    /**
     * @inheritDoc
     */
    public function execute(Observer $observer): void
    {
        $this->recentAuthentication->markNow();
    }
}
