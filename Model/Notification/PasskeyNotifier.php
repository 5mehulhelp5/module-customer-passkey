<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Model\Notification;

use DmLab\CustomerPasskey\Model\Config;
use Magento\Customer\Api\CustomerNameGenerationInterface;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Framework\App\Area;
use Magento\Framework\Mail\Template\TransportBuilder;
use Magento\Framework\Url;
use Magento\Store\Model\StoreManagerInterface;
use Psr\Log\LoggerInterface;

/**
 * Emails the customer when a passkey is added to or removed from their account,
 * so an enrolment by a session hijacker does not go unnoticed. Sending is
 * best-effort: any failure is logged and never breaks the calling flow.
 */
class PasskeyNotifier
{
    /**
     * @param Config $config
     * @param TransportBuilder $transportBuilder
     * @param StoreManagerInterface $storeManager
     * @param CustomerNameGenerationInterface $nameGeneration
     * @param Url $urlBuilder frontend URL builder (non-shared, see etc/di.xml)
     * @param LoggerInterface $logger
     */
    public function __construct(
        private readonly Config $config,
        private readonly TransportBuilder $transportBuilder,
        private readonly StoreManagerInterface $storeManager,
        private readonly CustomerNameGenerationInterface $nameGeneration,
        private readonly Url $urlBuilder,
        private readonly LoggerInterface $logger
    ) {
    }

    /**
     * Tell the customer a passkey was added.
     *
     * @param CustomerInterface $customer
     * @param string $label
     */
    public function notifyAdded(CustomerInterface $customer, string $label): void
    {
        $this->send($customer, $label, true);
    }

    /**
     * Tell the customer a passkey was removed.
     *
     * @param CustomerInterface $customer
     * @param string $label
     */
    public function notifyRemoved(CustomerInterface $customer, string $label): void
    {
        $this->send($customer, $label, false);
    }

    /**
     * Send the resolved template in the customer's store; failures are logged.
     *
     * @param CustomerInterface $customer
     * @param string $label
     * @param bool $added
     */
    private function send(CustomerInterface $customer, string $label, bool $added): void
    {
        try {
            $storeId = $this->resolveStoreId($customer);
            if (!$this->config->isNotificationEnabled($storeId)) {
                return;
            }

            $name = $this->nameGeneration->getCustomerName($customer);
            $label = trim($label);

            $template = $added
                ? $this->config->getAddedTemplate($storeId)
                : $this->config->getRemovedTemplate($storeId);

            $this->transportBuilder
                ->setTemplateIdentifier($template)
                ->setTemplateOptions(['area' => Area::AREA_FRONTEND, 'store' => $storeId])
                ->setTemplateVars([
                    'customer_name' => $name,
                    'passkey_label' => $label !== '' ? $label : (string)__('Passkey'),
                    'store_name' => $this->storeManager->getStore($storeId)->getFrontendName(),
                    'manage_url' => $this->manageUrl($storeId),
                ])
                ->setFromByScope($this->config->getNotificationIdentity($storeId), $storeId)
                ->addTo((string)$customer->getEmail(), $name)
                ->getTransport()
                ->sendMessage();
        } catch (\Throwable $e) {
            $this->logger->error('DmLab_CustomerPasskey: passkey notification failed.', ['exception' => $e]);
        }
    }

    /**
     * The customer's store, or their website's first store when unassigned (admin-created).
     *
     * @param CustomerInterface $customer
     */
    private function resolveStoreId(CustomerInterface $customer): int
    {
        $storeId = (int)$customer->getStoreId();
        if ($storeId > 0) {
            return $storeId;
        }

        $storeIds = $this->storeManager->getWebsite((int)$customer->getWebsiteId())->getStoreIds();

        return (int)reset($storeIds);
    }

    /**
     * The My Account passkeys page URL in the given store.
     *
     * @param int $storeId
     */
    private function manageUrl(int $storeId): string
    {
        $params = ['_nosid' => true];
        if ((int)$this->storeManager->getStore()->getId() !== $storeId) {
            $params['_scope_to_url'] = true;
        }

        return $this->urlBuilder->setScope($storeId)->getUrl('customerpasskey/manage', $params);
    }
}
