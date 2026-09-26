<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Controller\Manage;

use DmLab\CustomerPasskey\Model\CredentialRepository;
use Magento\Customer\Controller\AccountInterface;
use Magento\Customer\Model\Session;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;

/**
 * Deletes one of the signed-in customer's passkeys.
 *
 * The target is resolved only within the customer's own credential set
 * ({@see CredentialRepository::findOwnedByCustomer()}), so a forged `entity_id`
 * pointing at another shopper's passkey resolves to nothing and is refused — a
 * customer can only remove their own credentials. Implements {@see AccountInterface}
 * for the customer auth gate; the session check here is defence in depth.
 */
class Delete implements HttpPostActionInterface, AccountInterface
{
    /**
     * @param Session $customerSession
     * @param RequestInterface $request
     * @param CredentialRepository $credentials
     * @param JsonFactory $resultJsonFactory
     */
    public function __construct(
        private readonly Session $customerSession,
        private readonly RequestInterface $request,
        private readonly CredentialRepository $credentials,
        private readonly JsonFactory $resultJsonFactory
    ) {
    }

    /**
     * Remove the passkey, or a JSON error (403 anonymous / 404 not owned).
     *
     * @return Json
     */
    public function execute(): Json
    {
        $result = $this->resultJsonFactory->create();

        if (!$this->customerSession->isLoggedIn()) {
            return $this->error($result, 403, __('Please sign in to manage your passkeys.'));
        }

        $credential = $this->credentials->findOwnedByCustomer(
            (int)$this->customerSession->getCustomerId(),
            (int)$this->request->getParam('entity_id', 0)
        );
        if ($credential === null) {
            return $this->error($result, 404, __('Passkey not found.'));
        }

        $this->credentials->delete($credential);

        return $result->setData(['success' => true, 'message' => __('Passkey removed.')]);
    }

    /**
     * Emit a JSON error with the given HTTP status.
     *
     * @param Json $result
     * @param int $code
     * @param \Magento\Framework\Phrase $message
     */
    private function error(Json $result, int $code, \Magento\Framework\Phrase $message): Json
    {
        return $result->setHttpResponseCode($code)->setData([
            'success' => false,
            'message' => $message,
        ]);
    }
}
