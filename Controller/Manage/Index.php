<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Controller\Manage;

use Magento\Customer\Controller\AccountInterface;
use Magento\Framework\App\Action\HttpGetActionInterface;
use Magento\Framework\View\Result\Page;
use Magento\Framework\View\Result\PageFactory;

/**
 * The "Passkeys" My Account page: renders the customer's registered passkeys with
 * add-new (registration ceremony), rename and delete controls.
 *
 * Implements {@see AccountInterface} so Magento's customer auth plugin gates the
 * page — an anonymous visitor is redirected to login before dispatch, and the
 * block only ever sees the signed-in customer's own credentials.
 */
class Index implements HttpGetActionInterface, AccountInterface
{
    /**
     * @param PageFactory $resultPageFactory
     */
    public function __construct(
        private readonly PageFactory $resultPageFactory
    ) {
    }

    /**
     * Render the manage-passkeys page.
     *
     * @return Page
     */
    public function execute(): Page
    {
        return $this->resultPageFactory->create();
    }
}
