<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Authentication;

use DmLab\CustomerPasskey\Model\Authentication\RequestOptionsFactory;
use DmLab\CustomerPasskey\Model\Config;
use PHPUnit\Framework\TestCase;

class RequestOptionsFactoryTest extends TestCase
{
    /** @var RequestOptionsFactory */
    private RequestOptionsFactory $factory;

    protected function setUp(): void
    {
        $config = $this->createStub(Config::class);
        $config->method('getRpId')->willReturn('acme.test');
        $config->method('getUserVerification')->willReturn(Config::USER_VERIFICATION_REQUIRED);
        $config->method('getTimeout')->willReturn(45000);

        $this->factory = new RequestOptionsFactory($config);
    }

    public function testOptionsAreDiscoverableFromConfig(): void
    {
        $options = $this->factory->create();

        self::assertSame('acme.test', $options->rpId);
        self::assertSame(Config::USER_VERIFICATION_REQUIRED, $options->userVerification);
        self::assertSame(45000, $options->timeout);
        self::assertSame([], $options->allowCredentials);
        self::assertSame(32, strlen($options->challenge));
    }

    public function testAllowCredentialsEmptyForAnyStore(): void
    {
        self::assertSame([], $this->factory->create(1)->allowCredentials);
        self::assertSame([], $this->factory->create('default')->allowCredentials);
    }

    public function testRpIdIsNullWhenHostUnresolvable(): void
    {
        $config = $this->createStub(Config::class);
        $config->method('getRpId')->willReturn('');
        $config->method('getUserVerification')->willReturn(Config::USER_VERIFICATION_PREFERRED);
        $config->method('getTimeout')->willReturn(60000);

        $options = (new RequestOptionsFactory($config))->create();

        self::assertNull($options->rpId);
    }

    public function testChallengeIsFreshEachCall(): void
    {
        self::assertNotSame($this->factory->create()->challenge, $this->factory->create()->challenge);
    }
}
