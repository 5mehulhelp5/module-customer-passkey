<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Observer;

use DmLab\CustomerPasskey\Model\Security\RecentAuthentication;
use DmLab\CustomerPasskey\Observer\MarkRecentAuthentication;
use Magento\Framework\Event\Observer;
use PHPUnit\Framework\TestCase;

class MarkRecentAuthenticationTest extends TestCase
{
    public function testMarksSessionOnLogin(): void
    {
        $recent = $this->createMock(RecentAuthentication::class);
        $recent->expects(self::once())->method('markNow');

        (new MarkRecentAuthentication($recent))->execute($this->createStub(Observer::class));
    }
}
