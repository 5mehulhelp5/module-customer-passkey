<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Controller\Adminhtml\Customer;

use DmLab\CustomerPasskey\Model\CredentialRepository;
use DmLab\CustomerPasskey\Model\Notification\PasskeyNotifier;
use Magento\Backend\App\Action;
use Magento\Backend\App\Action\Context;
use Magento\Backend\Model\View\Result\Redirect;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\Exception\NoSuchEntityException;

/**
 * Revokes one of a customer's passkeys from the admin customer edit page (lost
 * device). The credential is resolved within the given customer's own set, so a
 * mismatched `customer_id`/`entity_id` pair is refused.
 */
class Revoke extends Action implements HttpPostActionInterface
{
    public const ADMIN_RESOURCE = 'DmLab_CustomerPasskey::manage';

    /**
     * @param Context $context
     * @param CredentialRepository $credentials
     * @param CustomerRepositoryInterface $customerRepository
     * @param PasskeyNotifier $notifier
     */
    public function __construct(
        Context $context,
        private readonly CredentialRepository $credentials,
        private readonly CustomerRepositoryInterface $customerRepository,
        private readonly PasskeyNotifier $notifier
    ) {
        parent::__construct($context);
    }

    /**
     * Delete the passkey and notify the customer, then return to the customer edit page.
     *
     * @return Redirect
     */
    public function execute(): Redirect
    {
        $customerId = (int)$this->getRequest()->getParam('customer_id', 0);
        $entityId = (int)$this->getRequest()->getParam('entity_id', 0);

        $redirect = $this->resultRedirectFactory->create();
        if ($customerId > 0) {
            $redirect->setPath('customer/index/edit', ['id' => $customerId]);
        } else {
            $redirect->setPath('customer/index');
        }

        $credential = $this->credentials->findOwnedByCustomer($customerId, $entityId);
        if ($credential === null) {
            $this->messageManager->addErrorMessage(__('Passkey not found.'));
            return $redirect;
        }

        try {
            $customer = $this->customerRepository->getById($customerId);
        } catch (NoSuchEntityException) {
            $this->messageManager->addErrorMessage(__('Passkey not found.'));
            return $redirect;
        }

        $this->credentials->delete($credential);
        $this->notifier->notifyRemoved($customer, (string)$credential->label);
        $this->messageManager->addSuccessMessage(__('The passkey has been revoked.'));

        return $redirect;
    }
}
