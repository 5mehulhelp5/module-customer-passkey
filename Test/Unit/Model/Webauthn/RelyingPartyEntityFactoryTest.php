<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Webauthn;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Webauthn\RelyingPartyEntityFactory;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[AllowMockObjectsWithoutExpectations]
class RelyingPartyEntityFactoryTest extends TestCase
{
    /** @var Config&MockObject */
    private $config;

    /** @var RelyingPartyEntityFactory */
    private RelyingPartyEntityFactory $factory;

    protected function setUp(): void
    {
        $this->config = $this->createMock(Config::class);
        $this->factory = new RelyingPartyEntityFactory($this->config);
    }

    public function testCreateUsesHostAsIdAndLeavesDeprecatedNameEmpty(): void
    {
        $this->config->method('getRpId')->willReturn('shop.example.com');

        $entity = $this->factory->create();

        // rp.name is emitted by OptionsSerializer; the library deprecates the entity name.
        self::assertSame('', $entity->name);
        self::assertSame('shop.example.com', $entity->id);
    }

    public function testCreateLeavesIdNullWhenHostUnresolvable(): void
    {
        $this->config->method('getRpId')->willReturn('');

        $entity = $this->factory->create();

        self::assertNull($entity->id);
    }
}
