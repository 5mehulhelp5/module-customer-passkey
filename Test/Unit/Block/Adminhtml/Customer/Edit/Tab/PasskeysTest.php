<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Block\Adminhtml\Customer\Edit\Tab;

use DmLab\CustomerPasskey\Block\Adminhtml\Customer\Edit\Tab\Passkeys;
use DmLab\CustomerPasskey\Model\Credential;
use DmLab\CustomerPasskey\Model\CredentialRepository;
use Magento\Backend\Block\Template\Context;
use Magento\Directory\Helper\Data as DirectoryHelper;
use Magento\Framework\App\ObjectManager as AppObjectManager;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\AuthorizationInterface;
use Magento\Framework\Json\Helper\Data as JsonHelper;
use Magento\Framework\TestFramework\Unit\Helper\ObjectManager;
use Magento\Framework\UrlInterface;
use Magento\Ui\Component\Layout\Tabs\TabInterface;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\TestCase;

#[AllowMockObjectsWithoutExpectations]
class PasskeysTest extends TestCase
{
    protected function tearDown(): void
    {
        // The backend Template constructor pulls helpers from the global ObjectManager; don't leak the mock.
        (new \ReflectionProperty(AppObjectManager::class, '_instance'))->setValue(null, null);
    }

    /**
     * @param Credential[] $passkeys
     */
    private function block(?int $customerId = 42, bool $allowed = true, array $passkeys = []): Passkeys
    {
        $request = $this->createStub(RequestInterface::class);
        $request->method('getParam')->willReturnMap([['id', 0, $customerId]]);

        $authorization = $this->createMock(AuthorizationInterface::class);
        $authorization->method('isAllowed')->willReturnMap([['DmLab_CustomerPasskey::manage', null, $allowed]]);

        $url = $this->createStub(UrlInterface::class);
        $url->method('getUrl')->willReturnCallback(
            static fn(string $route): string => 'https://acme.test/admin/' . $route
        );

        $context = $this->createStub(Context::class);
        $context->method('getRequest')->willReturn($request);
        $context->method('getAuthorization')->willReturn($authorization);
        $context->method('getUrlBuilder')->willReturn($url);

        $credentials = $this->createStub(CredentialRepository::class);
        $credentials->method('listByCustomer')->willReturnMap([[(int)$customerId, $passkeys]]);

        $objectManager = new ObjectManager($this);
        $objectManager->prepareObjectManager([
            [JsonHelper::class, $this->createStub(JsonHelper::class)],
            [DirectoryHelper::class, $this->createStub(DirectoryHelper::class)],
        ]);

        return $objectManager->getObject(Passkeys::class, [
            'context' => $context,
            'credentials' => $credentials,
        ]);
    }

    public function testIsAUiTab(): void
    {
        $block = $this->block();

        self::assertInstanceOf(TabInterface::class, $block);
        self::assertSame('Passkeys', (string)$block->getTabLabel());
        self::assertSame('Passkeys', (string)$block->getTabTitle());
        self::assertFalse($block->isAjaxLoaded());
        self::assertSame('', $block->getTabUrl());
        self::assertFalse($block->isHidden());
    }

    public function testShownForExistingCustomerWhenAllowed(): void
    {
        self::assertTrue($this->block(42, true)->canShowTab());
    }

    public function testHiddenOnNewCustomerPage(): void
    {
        self::assertFalse($this->block(null, true)->canShowTab());
    }

    public function testHiddenWithoutAcl(): void
    {
        self::assertFalse($this->block(42, false)->canShowTab());
    }

    public function testListsTheEditedCustomersPasskeys(): void
    {
        $passkeys = [new Credential(entityId: 7, customerId: 42, credentialId: 'a', aaguid: 'x')];
        $block = $this->block(42, true, $passkeys);

        self::assertSame(42, $block->getCustomerId());
        self::assertSame($passkeys, $block->getPasskeys());
    }

    public function testLabelAndDateFallbacks(): void
    {
        $block = $this->block();

        self::assertSame('My phone', $block->getLabel(new Credential(label: 'My phone')));
        self::assertSame('Passkey', $block->getLabel(new Credential(label: ' ')));
        self::assertSame('—', $block->renderDate(null));
    }

    public function testRevokeUrl(): void
    {
        self::assertSame('https://acme.test/admin/customerpasskey/customer/revoke', $this->block()->getRevokeUrl());
    }
}
