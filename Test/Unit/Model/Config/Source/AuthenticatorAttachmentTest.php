<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Config\Source;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Config\Source\AuthenticatorAttachment;
use PHPUnit\Framework\TestCase;

class AuthenticatorAttachmentTest extends TestCase
{
    public function testToOptionArrayExposesEveryAttachment(): void
    {
        $values = array_column((new AuthenticatorAttachment())->toOptionArray(), 'value');

        self::assertSame([
            Config::ATTACHMENT_ANY,
            Config::ATTACHMENT_PLATFORM,
            Config::ATTACHMENT_CROSS_PLATFORM,
        ], $values);
    }
}
