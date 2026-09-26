<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Webauthn;

use DmLab\CustomerPasskey\Model\Webauthn\ChallengeStorage;
use Magento\Customer\Model\Session;
use Magento\Framework\TestFramework\Unit\Helper\MockCreationTrait;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;

// The customer Session is mocked only to back the store with an in-memory slot;
// its setData/getData/unsetData are magic methods a stub cannot express.
#[AllowMockObjectsWithoutExpectations]
class ChallengeStorageTest extends TestCase
{
    use MockCreationTrait;

    /** @var array<string,mixed> */
    private array $store = [];

    /** @var ChallengeStorage */
    private ChallengeStorage $storage;

    protected function setUp(): void
    {
        $this->store = [];

        $session = $this->createPartialMockWithReflection(Session::class, ['getData', 'setData', 'unsetData']);
        $session->expects($this->any())->method('getData')
            ->willReturnCallback(fn($key) => $this->store[$key] ?? null);
        $session->expects($this->any())->method('setData')
            ->willReturnCallback(function ($key, $value): void {
                $this->store[$key] = $value;
            });
        $session->expects($this->any())->method('unsetData')
            ->willReturnCallback(function ($key): void {
                unset($this->store[$key]);
            });

        $this->storage = new ChallengeStorage($session);
    }

    public function testChallengeIsConsumedOnce(): void
    {
        $this->storage->save('challenge-bytes');

        self::assertSame(
            ['challenge' => 'challenge-bytes', 'scope' => null],
            $this->storage->consume()
        );
        // Single-use: a replayed ceremony finds nothing.
        self::assertNull($this->storage->consume());
    }

    public function testConsumeWithoutSaveReturnsNull(): void
    {
        self::assertNull($this->storage->consume());
    }

    public function testBinaryChallengeRoundTrips(): void
    {
        $raw = "\x00\x01\xff\xfe\x10challenge";
        $this->storage->save($raw);

        self::assertSame(['challenge' => $raw, 'scope' => null], $this->storage->consume());
    }

    public function testSaveReplacesPendingChallenge(): void
    {
        $this->storage->save('first');
        $this->storage->save('second');

        self::assertSame(['challenge' => 'second', 'scope' => null], $this->storage->consume());
        self::assertNull($this->storage->consume());
    }

    public function testLoginScopeIsBoundToTheChallenge(): void
    {
        $this->storage->save('scoped', 42);

        self::assertSame(['challenge' => 'scoped', 'scope' => 42], $this->storage->consume());
    }

    public function testUnknownEmailScopeRoundTripsAsZero(): void
    {
        $this->storage->save('scoped', 0);

        self::assertSame(['challenge' => 'scoped', 'scope' => 0], $this->storage->consume());
    }
}
