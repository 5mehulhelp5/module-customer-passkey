<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model;

use DmLab\CustomerPasskey\Model\Config;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Store\Model\ScopeInterface;
use Magento\Store\Model\Store;
use Magento\Store\Model\StoreManagerInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[AllowMockObjectsWithoutExpectations]
class ConfigTest extends TestCase
{
    /** @var ScopeConfigInterface&MockObject */
    private $scopeConfig;

    /** @var StoreManagerInterface&MockObject */
    private $storeManager;

    /** @var Config */
    private Config $config;

    protected function setUp(): void
    {
        $this->scopeConfig = $this->createMock(ScopeConfigInterface::class);
        $this->storeManager = $this->createMock(StoreManagerInterface::class);
        $this->config = new Config($this->scopeConfig, $this->storeManager);
    }

    public function testIsEnabledDelegatesToFlag(): void
    {
        $this->scopeConfig->method('isSetFlag')
            ->with(Config::XML_PATH_ENABLED, ScopeInterface::SCOPE_STORE, 1)
            ->willReturn(true);

        self::assertTrue($this->config->isEnabled(1));
    }

    public function testGetRpDisplayNameReturnsConfiguredValue(): void
    {
        $this->scopeConfig->method('getValue')
            ->with(Config::XML_PATH_RP_DISPLAY_NAME, ScopeInterface::SCOPE_STORE, null)
            ->willReturn('  Acme Store  ');

        self::assertSame('Acme Store', $this->config->getRpDisplayName());
    }

    public function testGetRpDisplayNameFallsBackToStoreName(): void
    {
        $this->scopeConfig->method('getValue')->willReturnMap([
            [Config::XML_PATH_RP_DISPLAY_NAME, ScopeInterface::SCOPE_STORE, null, ''],
            ['general/store_information/name', ScopeInterface::SCOPE_STORE, null, 'Fallback Shop'],
        ]);

        self::assertSame('Fallback Shop', $this->config->getRpDisplayName());
    }

    public function testGetRpDisplayNameFallsBackToMagentoWhenAllEmpty(): void
    {
        $this->scopeConfig->method('getValue')->willReturn('');

        self::assertSame('Magento', $this->config->getRpDisplayName());
    }

    public function testGetUserVerificationReturnsConfiguredValue(): void
    {
        $this->scopeConfig->method('getValue')
            ->with(Config::XML_PATH_USER_VERIFICATION, ScopeInterface::SCOPE_STORE, null)
            ->willReturn(Config::USER_VERIFICATION_REQUIRED);

        self::assertSame(Config::USER_VERIFICATION_REQUIRED, $this->config->getUserVerification());
    }

    public function testGetUserVerificationFallsBackToPreferred(): void
    {
        $this->scopeConfig->method('getValue')
            ->with(Config::XML_PATH_USER_VERIFICATION, ScopeInterface::SCOPE_STORE, null)
            ->willReturn('nonsense');

        self::assertSame(Config::USER_VERIFICATION_PREFERRED, $this->config->getUserVerification());
    }

    public function testGetAuthenticatorAttachmentReturnsConfiguredValue(): void
    {
        $this->scopeConfig->method('getValue')
            ->with(Config::XML_PATH_AUTHENTICATOR_ATTACHMENT, ScopeInterface::SCOPE_STORE, null)
            ->willReturn(Config::ATTACHMENT_PLATFORM);

        self::assertSame(Config::ATTACHMENT_PLATFORM, $this->config->getAuthenticatorAttachment());
    }

    public function testGetAuthenticatorAttachmentFallsBackToAny(): void
    {
        $this->scopeConfig->method('getValue')
            ->with(Config::XML_PATH_AUTHENTICATOR_ATTACHMENT, ScopeInterface::SCOPE_STORE, null)
            ->willReturn('');

        self::assertSame(Config::ATTACHMENT_ANY, $this->config->getAuthenticatorAttachment());
    }

    public function testGetTimeoutReturnsConfiguredValue(): void
    {
        $this->scopeConfig->method('getValue')
            ->with(Config::XML_PATH_TIMEOUT, ScopeInterface::SCOPE_STORE, null)
            ->willReturn('90000');

        self::assertSame(90000, $this->config->getTimeout());
    }

    public function testGetTimeoutFallsBackWhenNonPositive(): void
    {
        $this->scopeConfig->method('getValue')
            ->with(Config::XML_PATH_TIMEOUT, ScopeInterface::SCOPE_STORE, null)
            ->willReturn('0');

        self::assertSame(Config::DEFAULT_TIMEOUT, $this->config->getTimeout());
    }

    public function testIsPasswordlessAllowedDelegatesToFlag(): void
    {
        $this->scopeConfig->method('isSetFlag')
            ->with(Config::XML_PATH_ALLOW_PASSWORDLESS, ScopeInterface::SCOPE_STORE, null)
            ->willReturn(false);

        self::assertFalse($this->config->isPasswordlessAllowed());
    }

    public function testGetRpIdExtractsHostFromBaseUrl(): void
    {
        $store = $this->createMock(Store::class);
        $store->method('getBaseUrl')->willReturn('https://shop.example.com:8443/path/');
        $this->storeManager->method('getStore')->with(2)->willReturn($store);

        self::assertSame('shop.example.com', $this->config->getRpId(2));
    }

    public function testGetRpIdReturnsEmptyWhenNoHost(): void
    {
        $store = $this->createMock(Store::class);
        $store->method('getBaseUrl')->willReturn('not a url');
        $this->storeManager->method('getStore')->willReturn($store);

        self::assertSame('', $this->config->getRpId());
    }
}
