<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Block\Manage;

use DmLab\CustomerPasskey\Block\Manage\ListPasskeys;
use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Credential;
use DmLab\CustomerPasskey\Model\CredentialRepository;
use Magento\Customer\Model\Session;
use Magento\Framework\Data\Form\FormKey;
use Magento\Framework\Serialize\Serializer\Json;
use Magento\Framework\TestFramework\Unit\Helper\ObjectManager;
use Magento\Framework\UrlInterface;
use Magento\Framework\View\Element\Template\Context;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;

#[AllowMockObjectsWithoutExpectations]
class ListPasskeysTest extends TestCase
{
    /**
     * @param Credential[] $passkeys
     */
    private function block(
        bool $enabled = true,
        int $customerId = 42,
        array $passkeys = [],
        ?UrlInterface $url = null
    ): ListPasskeys {
        $config = $this->createStub(Config::class);
        $config->method('isEnabled')->willReturn($enabled);

        $session = $this->createStub(Session::class);
        $session->method('getCustomerId')->willReturn($customerId);

        $credentials = $this->createStub(CredentialRepository::class);
        $credentials->method('listByCustomer')->willReturnMap([[$customerId, $passkeys]]);

        $formKey = $this->createStub(FormKey::class);
        $formKey->method('getFormKey')->willReturn('formkey-123');

        $context = $this->createStub(Context::class);
        $context->method('getUrlBuilder')->willReturn($url ?? $this->createStub(UrlInterface::class));

        return (new ObjectManager($this))->getObject(ListPasskeys::class, [
            'context' => $context,
            'config' => $config,
            'customerSession' => $session,
            'credentials' => $credentials,
            'formKey' => $formKey,
            'json' => new Json(),
        ]);
    }

    public function testIsEnabledReflectsConfig(): void
    {
        self::assertTrue($this->block(true)->isEnabled());
        self::assertFalse($this->block(false)->isEnabled());
    }

    public function testListsOnlyTheCurrentCustomersPasskeys(): void
    {
        $passkeys = [new Credential(entityId: 7, customerId: 42, credentialId: 'a')];
        $block = $this->block(true, 42, $passkeys);

        self::assertSame($passkeys, $block->getPasskeys());
        self::assertTrue($block->hasPasskeys());
    }

    public function testHasPasskeysFalseWhenNone(): void
    {
        self::assertFalse($this->block(true, 42, [])->hasPasskeys());
    }

    public function testLabelFallsBackToGenericName(): void
    {
        $block = $this->block();

        self::assertSame('My laptop', $block->getLabel(new Credential(label: 'My laptop')));
        self::assertSame('Passkey', $block->getLabel(new Credential(label: '  ')));
        self::assertSame('Passkey', $block->getLabel(new Credential(label: null)));
    }

    public function testRenderDateEmDashWhenNeverSet(): void
    {
        self::assertSame('—', $this->block()->renderDate(null));
        self::assertSame('—', $this->block()->renderDate(''));
    }

    public function testJsonConfigCarriesEndpointsAndFormKey(): void
    {
        $url = $this->createMock(UrlInterface::class);
        $url->method('getUrl')->willReturnCallback(
            static fn(string $route): string => 'https://acme.test/' . $route
        );

        $config = json_decode($this->block(true, 42, [], $url)->getJsonConfig(), true);

        self::assertSame('https://acme.test/customerpasskey/register/options', $config['optionsUrl']);
        self::assertSame('https://acme.test/customerpasskey/register/verify', $config['verifyUrl']);
        self::assertSame('https://acme.test/customerpasskey/manage/rename', $config['renameUrl']);
        self::assertSame('https://acme.test/customerpasskey/manage/delete', $config['deleteUrl']);
        self::assertSame('formkey-123', $config['formKey']);
    }
}
