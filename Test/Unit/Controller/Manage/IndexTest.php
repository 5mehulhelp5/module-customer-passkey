<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Test\Unit\Controller\Manage;

use MageDevGroup\CustomerPasskey\Controller\Manage\Index;
use Magento\Customer\Controller\AccountInterface;
use Magento\Framework\App\Action\HttpGetActionInterface;
use Magento\Framework\View\Result\Page;
use Magento\Framework\View\Result\PageFactory;
use PHPUnit\Framework\TestCase;

class IndexTest extends TestCase
{
    public function testRendersPage(): void
    {
        $page = $this->createStub(Page::class);
        $pageFactory = $this->createMock(PageFactory::class);
        $pageFactory->expects(self::once())->method('create')->willReturn($page);

        self::assertSame($page, (new Index($pageFactory))->execute());
    }

    public function testIsGuardedByCustomerAuth(): void
    {
        // Implementing AccountInterface makes Magento's customer auth plugin
        // redirect anonymous visitors to login before dispatch.
        $controller = new Index($this->createStub(PageFactory::class));

        self::assertInstanceOf(AccountInterface::class, $controller);
        self::assertInstanceOf(HttpGetActionInterface::class, $controller);
    }
}
