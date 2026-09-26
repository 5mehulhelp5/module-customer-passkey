<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Block\Login;

use DmLab\CustomerPasskey\Block\Login\Passkey;
use DmLab\CustomerPasskey\Model\Config;
use Magento\Framework\Data\Form\FormKey;
use Magento\Framework\Serialize\Serializer\Json;
use Magento\Framework\TestFramework\Unit\Helper\ObjectManager;
use Magento\Framework\UrlInterface;
use Magento\Framework\View\Element\Template\Context;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;

#[AllowMockObjectsWithoutExpectations]
class PasskeyTest extends TestCase
{
    private function block(bool $enabled, bool $passwordless, ?UrlInterface $url = null): Passkey
    {
        $config = $this->createStub(Config::class);
        $config->method('isEnabled')->willReturn($enabled);
        $config->method('isPasswordlessAllowed')->willReturn($passwordless);

        $formKey = $this->createStub(FormKey::class);
        $formKey->method('getFormKey')->willReturn('formkey-123');

        $context = $this->createStub(Context::class);
        $context->method('getUrlBuilder')->willReturn($url ?? $this->createStub(UrlInterface::class));

        return (new ObjectManager($this))->getObject(Passkey::class, [
            'context' => $context,
            'config' => $config,
            'formKey' => $formKey,
            'json' => new Json(),
        ]);
    }

    public function testAvailableWhenEnabledAndPasswordlessAllowed(): void
    {
        $block = $this->block(true, true);

        self::assertTrue($block->isAvailable());
        self::assertSame('Sign in with a passkey', $block->getButtonLabel());
    }

    public function testHiddenWhenModuleDisabled(): void
    {
        self::assertFalse($this->block(false, true)->isAvailable());
    }

    public function testHiddenWhenPasswordlessDisabled(): void
    {
        // No discoverable passkey login available → the button is not shown.
        self::assertFalse($this->block(true, false)->isAvailable());
    }

    public function testRendersNothingWhenNotAvailable(): void
    {
        $toHtml = new \ReflectionMethod($this->block(false, false), '_toHtml');

        self::assertSame('', $toHtml->invoke($this->block(false, false)));
    }

    public function testJsonConfigCarriesEndpointsAndFormKey(): void
    {
        $url = $this->createMock(UrlInterface::class);
        $url->method('getUrl')->willReturnCallback(
            static fn(string $route): string => 'https://acme.test/' . $route
        );

        $config = json_decode($this->block(true, true, $url)->getJsonConfig(), true);

        self::assertSame('https://acme.test/customerpasskey/login/options', $config['optionsUrl']);
        self::assertSame('https://acme.test/customerpasskey/login/verify', $config['verifyUrl']);
        self::assertSame('formkey-123', $config['formKey']);
    }
}
