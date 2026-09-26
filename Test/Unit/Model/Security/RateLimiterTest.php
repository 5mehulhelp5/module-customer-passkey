<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Security;

use DmLab\CustomerPasskey\Model\Security\RateLimiter;
use Magento\Framework\App\CacheInterface;
use Magento\Framework\HTTP\PhpEnvironment\RemoteAddress;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[AllowMockObjectsWithoutExpectations]
class RateLimiterTest extends TestCase
{
    /** @var CacheInterface&MockObject */
    private $cache;

    /** @var RemoteAddress&MockObject */
    private $remoteAddress;

    /** @var RateLimiter */
    private RateLimiter $limiter;

    protected function setUp(): void
    {
        $this->cache = $this->createMock(CacheInterface::class);
        $this->remoteAddress = $this->createMock(RemoteAddress::class);
        $this->remoteAddress->method('getRemoteAddress')->willReturn('203.0.113.7');

        $this->limiter = new RateLimiter($this->cache, $this->remoteAddress);
    }

    public function testAllowsAndIncrementsFirstAttempt(): void
    {
        $this->cache->method('load')->willReturn(false);

        $this->cache->expects(self::once())->method('save')
            ->with('1', self::isString(), self::isArray(), 60);

        self::assertTrue($this->limiter->registerAttempt('login_verify', 10, 60));
    }

    public function testAllowsWhileUnderLimitAndCarriesTheWindow(): void
    {
        $this->cache->method('load')->willReturn('3');

        $this->cache->expects(self::once())->method('save')
            ->with('4', self::isString(), self::isArray(), 90);

        self::assertTrue($this->limiter->registerAttempt('login_verify', 10, 90));
    }

    public function testAllowsTheLastAttemptBeforeTheLimit(): void
    {
        $this->cache->method('load')->willReturn('9');

        $this->cache->expects(self::once())->method('save')
            ->with('10', self::isString(), self::isArray(), 60);

        self::assertTrue($this->limiter->registerAttempt('login_verify', 10, 60));
    }

    public function testBlocksAtLimitWithoutExtendingTheWindow(): void
    {
        $this->cache->method('load')->willReturn('10');

        $this->cache->expects(self::never())->method('save');

        self::assertFalse($this->limiter->registerAttempt('login_verify', 10, 60));
    }

    public function testCountersAreScopedPerBucketAndClient(): void
    {
        $this->cache->method('load')->willReturn(false);

        $keys = [];
        $this->cache->method('save')->willReturnCallback(
            function (string $data, string $key) use (&$keys): bool {
                $keys[] = $key;

                return true;
            }
        );

        $this->limiter->registerAttempt('login_verify', 10, 60);
        $this->limiter->registerAttempt('register_verify', 10, 60);

        self::assertNotSame($keys[0], $keys[1], 'Distinct buckets must use distinct cache keys.');
        self::assertStringContainsString('login_verify', $keys[0]);
        self::assertStringContainsString('register_verify', $keys[1]);
    }

    public function testFallsBackToAnUnknownClientWhenAddressIsUnavailable(): void
    {
        $remoteAddress = $this->createMock(RemoteAddress::class);
        $remoteAddress->method('getRemoteAddress')->willReturn(false);
        $limiter = new RateLimiter($this->cache, $remoteAddress);

        $this->cache->method('load')->willReturn(false);
        $this->cache->expects(self::once())->method('save')
            ->with('1', self::isString(), self::isArray(), 60);

        self::assertTrue($limiter->registerAttempt('login_verify', 10, 60));
    }
}
