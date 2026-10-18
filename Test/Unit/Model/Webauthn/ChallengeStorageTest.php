<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
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
        $this->storage->save(ChallengeStorage::CEREMONY_REGISTER, 'challenge-bytes');

        self::assertSame(
            ['challenge' => 'challenge-bytes', 'scope' => null],
            $this->storage->consume(ChallengeStorage::CEREMONY_REGISTER)
        );
        // Single-use: a replayed ceremony finds nothing.
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_REGISTER));
    }

    public function testLoginChallengeRoundTrips(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_LOGIN, 'login-bytes');

        self::assertSame(
            ['challenge' => 'login-bytes', 'scope' => null],
            $this->storage->consume(ChallengeStorage::CEREMONY_LOGIN)
        );
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
    }

    public function testConsumeWithoutSaveReturnsNull(): void
    {
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_REGISTER));
    }

    public function testLoginChallengeCannotCompleteRegistration(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_LOGIN, 'login-bytes', 42);

        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_REGISTER));
        // The mismatch burns the slot — the challenge cannot be retried for login either.
        self::assertSame([], $this->store);
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
    }

    public function testRegisterChallengeCannotCompleteLogin(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_REGISTER, 'register-bytes');

        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
        self::assertSame([], $this->store);
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_REGISTER));
    }

    public function testSlotWithoutCeremonyIsRejected(): void
    {
        // Pre-upgrade session format: no ceremony type.
        $this->store['dmlab_customer_passkey_challenge'] = (string)json_encode([
            'c' => base64_encode('legacy'),
            's' => null,
        ]);

        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
        self::assertSame([], $this->store);
    }

    public function testCorruptSlotIsRejectedAndCleared(): void
    {
        foreach (['not-json', (string)json_encode(['c' => 1, 't' => ChallengeStorage::CEREMONY_LOGIN])] as $slot) {
            $this->store['dmlab_customer_passkey_challenge'] = $slot;

            self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_LOGIN));
            self::assertSame([], $this->store);
        }
    }

    public function testBinaryChallengeRoundTrips(): void
    {
        $raw = "\x00\x01\xff\xfe\x10challenge";
        $this->storage->save(ChallengeStorage::CEREMONY_REGISTER, $raw);

        self::assertSame(
            ['challenge' => $raw, 'scope' => null],
            $this->storage->consume(ChallengeStorage::CEREMONY_REGISTER)
        );
    }

    public function testSaveReplacesPendingChallenge(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_LOGIN, 'first');
        $this->storage->save(ChallengeStorage::CEREMONY_REGISTER, 'second');

        self::assertSame(
            ['challenge' => 'second', 'scope' => null],
            $this->storage->consume(ChallengeStorage::CEREMONY_REGISTER)
        );
        self::assertNull($this->storage->consume(ChallengeStorage::CEREMONY_REGISTER));
    }

    public function testLoginScopeIsBoundToTheChallenge(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_LOGIN, 'scoped', 42);

        self::assertSame(
            ['challenge' => 'scoped', 'scope' => 42],
            $this->storage->consume(ChallengeStorage::CEREMONY_LOGIN)
        );
    }

    public function testUnknownEmailScopeRoundTripsAsZero(): void
    {
        $this->storage->save(ChallengeStorage::CEREMONY_LOGIN, 'scoped', 0);

        self::assertSame(
            ['challenge' => 'scoped', 'scope' => 0],
            $this->storage->consume(ChallengeStorage::CEREMONY_LOGIN)
        );
    }
}
