<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Config\Source;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Config\Source\UserVerification;
use PHPUnit\Framework\TestCase;

class UserVerificationTest extends TestCase
{
    public function testToOptionArrayExposesEveryLevel(): void
    {
        $values = array_column((new UserVerification())->toOptionArray(), 'value');

        self::assertSame([
            Config::USER_VERIFICATION_REQUIRED,
            Config::USER_VERIFICATION_PREFERRED,
            Config::USER_VERIFICATION_DISCOURAGED,
        ], $values);
    }
}
