<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Test\Unit\Model\Webauthn;

use MageDevGroup\CustomerPasskey\Model\Config;
use MageDevGroup\CustomerPasskey\Model\Webauthn\RelyingPartyEntityFactory;
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

    public function testCreateUsesDisplayNameAndHostAsId(): void
    {
        $this->config->method('getRpDisplayName')->willReturn('Example Store');
        $this->config->method('getRpId')->willReturn('shop.example.com');

        $entity = $this->factory->create();

        self::assertSame('Example Store', $entity->name);
        self::assertSame('shop.example.com', $entity->id);
    }

    public function testCreateLeavesIdNullWhenHostUnresolvable(): void
    {
        $this->config->method('getRpDisplayName')->willReturn('Example Store');
        $this->config->method('getRpId')->willReturn('');

        $entity = $this->factory->create();

        self::assertNull($entity->id);
    }
}
