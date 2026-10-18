<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Model\Notification;

use DmLab\CustomerPasskey\Model\Config;
use DmLab\CustomerPasskey\Model\Notification\PasskeyNotifier;
use Magento\Customer\Api\CustomerNameGenerationInterface;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Framework\App\Area;
use Magento\Framework\Exception\MailException;
use Magento\Framework\Mail\Template\TransportBuilder;
use Magento\Framework\Mail\TransportInterface;
use Magento\Framework\Url;
use Magento\Store\Model\Store;
use Magento\Store\Model\StoreManagerInterface;
use Magento\Store\Model\Website;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\LoggerInterface;

#[AllowMockObjectsWithoutExpectations]
class PasskeyNotifierTest extends TestCase
{
    private const STORE_ID = 3;

    /** @var Config&MockObject */
    private $config;

    /** @var TransportBuilder&MockObject */
    private $transportBuilder;

    /** @var TransportInterface&MockObject */
    private $transport;

    /** @var StoreManagerInterface&MockObject */
    private $storeManager;

    /** @var Url&MockObject */
    private $url;

    /** @var LoggerInterface&MockObject */
    private $logger;

    /** @var PasskeyNotifier */
    private PasskeyNotifier $notifier;

    protected function setUp(): void
    {
        $this->config = $this->createMock(Config::class);
        $this->config->method('getNotificationIdentity')->willReturn('general');
        $this->config->method('getAddedTemplate')->willReturn('added_tpl');
        $this->config->method('getRemovedTemplate')->willReturn('removed_tpl');

        $this->transport = $this->createMock(TransportInterface::class);
        $this->transportBuilder = $this->createMock(TransportBuilder::class);
        foreach (['setTemplateIdentifier', 'setTemplateOptions', 'setTemplateVars', 'setFromByScope', 'addTo'] as $m) {
            $this->transportBuilder->method($m)->willReturnSelf();
        }
        $this->transportBuilder->method('getTransport')->willReturn($this->transport);

        $store = $this->createMock(Store::class);
        $store->method('getId')->willReturn(self::STORE_ID);
        $store->method('getFrontendName')->willReturn('Acme Store');
        $this->storeManager = $this->createMock(StoreManagerInterface::class);
        $this->storeManager->method('getStore')->willReturn($store);

        $this->url = $this->createMock(Url::class);
        $this->url->method('setScope')->willReturnSelf();
        $this->url->method('getUrl')->willReturn('https://shop.test/customerpasskey/manage/');

        $nameGeneration = $this->createStub(CustomerNameGenerationInterface::class);
        $nameGeneration->method('getCustomerName')->willReturn('Jane Shopper');

        $this->logger = $this->createMock(LoggerInterface::class);

        $this->notifier = new PasskeyNotifier(
            $this->config,
            $this->transportBuilder,
            $this->storeManager,
            $nameGeneration,
            $this->url,
            $this->logger
        );
    }

    private function customer(int $storeId = self::STORE_ID, int $websiteId = 1): CustomerInterface
    {
        $customer = $this->createStub(CustomerInterface::class);
        $customer->method('getStoreId')->willReturn($storeId);
        $customer->method('getWebsiteId')->willReturn($websiteId);
        $customer->method('getEmail')->willReturn('shopper@acme.test');

        return $customer;
    }

    public function testNotifyAddedSendsTemplateInCustomerStore(): void
    {
        $this->config->method('isNotificationEnabled')->with(self::STORE_ID)->willReturn(true);

        $this->transportBuilder->expects(self::once())->method('setTemplateIdentifier')->with('added_tpl');
        $this->transportBuilder->expects(self::once())->method('setTemplateOptions')
            ->with(['area' => Area::AREA_FRONTEND, 'store' => self::STORE_ID]);
        $this->transportBuilder->expects(self::once())->method('setTemplateVars')->with([
            'customer_name' => 'Jane Shopper',
            'passkey_label' => 'My laptop',
            'store_name' => 'Acme Store',
            'manage_url' => 'https://shop.test/customerpasskey/manage/',
        ]);
        $this->transportBuilder->expects(self::once())->method('setFromByScope')->with('general', self::STORE_ID);
        $this->transportBuilder->expects(self::once())->method('addTo')->with('shopper@acme.test', 'Jane Shopper');
        $this->url->expects(self::once())->method('setScope')->with(self::STORE_ID);
        $this->url->expects(self::once())->method('getUrl')->with('customerpasskey/manage', ['_nosid' => true]);
        $this->transport->expects(self::once())->method('sendMessage');
        $this->logger->expects(self::never())->method('error');

        $this->notifier->notifyAdded($this->customer(), ' My laptop ');
    }

    public function testNotifyRemovedUsesRemovedTemplateAndLabelFallback(): void
    {
        $this->config->method('isNotificationEnabled')->willReturn(true);

        $this->transportBuilder->expects(self::once())->method('setTemplateIdentifier')->with('removed_tpl');
        $this->transportBuilder->expects(self::once())->method('setTemplateVars')
            ->with(self::callback(static fn(array $v): bool => $v['passkey_label'] === 'Passkey'));
        $this->transport->expects(self::once())->method('sendMessage');

        $this->notifier->notifyRemoved($this->customer(), '');
    }

    public function testUnassignedCustomerFallsBackToWebsiteStore(): void
    {
        $website = $this->createMock(Website::class);
        $website->method('getStoreIds')->willReturn([5 => '5', 6 => '6']);
        $this->storeManager->method('getWebsite')->with(2)->willReturn($website);
        $this->config->expects(self::once())->method('isNotificationEnabled')->with(5)->willReturn(true);

        $this->transportBuilder->expects(self::once())->method('setTemplateOptions')
            ->with(['area' => Area::AREA_FRONTEND, 'store' => 5]);
        // The current store (3) differs from the customer's, so the URL carries its scope.
        $this->url->expects(self::once())->method('getUrl')
            ->with('customerpasskey/manage', ['_nosid' => true, '_scope_to_url' => true]);
        $this->transport->expects(self::once())->method('sendMessage');

        $this->notifier->notifyRemoved($this->customer(0, 2), 'Key');
    }

    public function testDisabledSendsNothing(): void
    {
        $this->config->method('isNotificationEnabled')->willReturn(false);

        $this->transportBuilder->expects(self::never())->method('setTemplateIdentifier');
        $this->transport->expects(self::never())->method('sendMessage');

        $this->notifier->notifyAdded($this->customer(), 'My laptop');
    }

    public function testTransportFailureIsLoggedNotThrown(): void
    {
        $this->config->method('isNotificationEnabled')->willReturn(true);
        $this->transport->method('sendMessage')->willThrowException(new MailException(__('SMTP down')));

        $this->logger->expects(self::once())->method('error')
            ->with(self::anything(), self::callback(
                static fn(array $c): bool => $c['exception'] instanceof MailException
            ));

        $this->notifier->notifyAdded($this->customer(), 'My laptop');
    }
}
