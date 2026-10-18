<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Controller\Adminhtml\Customer;

use DmLab\CustomerPasskey\Controller\Adminhtml\Customer\Revoke;
use DmLab\CustomerPasskey\Model\Credential;
use DmLab\CustomerPasskey\Model\CredentialRepository;
use DmLab\CustomerPasskey\Model\Notification\PasskeyNotifier;
use Magento\Backend\App\Action\Context;
use Magento\Backend\Model\View\Result\Redirect;
use Magento\Backend\Model\View\Result\RedirectFactory;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Framework\App\Action\HttpPostActionInterface;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Exception\NoSuchEntityException;
use Magento\Framework\Message\ManagerInterface;
use Magento\Framework\TestFramework\Unit\Helper\ObjectManager;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[AllowMockObjectsWithoutExpectations]
class RevokeTest extends TestCase
{
    /** @var RequestInterface&MockObject */
    private $request;

    /** @var CredentialRepository&MockObject */
    private $credentials;

    /** @var CustomerRepositoryInterface&MockObject */
    private $customers;

    /** @var PasskeyNotifier&MockObject */
    private $notifier;

    /** @var ManagerInterface&MockObject */
    private $messages;

    /** @var Redirect&MockObject */
    private $redirect;

    /** @var Revoke */
    private Revoke $controller;

    protected function setUp(): void
    {
        $this->request = $this->createMock(RequestInterface::class);
        $this->credentials = $this->createMock(CredentialRepository::class);
        $this->customers = $this->createMock(CustomerRepositoryInterface::class);
        $this->notifier = $this->createMock(PasskeyNotifier::class);
        $this->messages = $this->createMock(ManagerInterface::class);

        $this->redirect = $this->createMock(Redirect::class);
        $this->redirect->method('setPath')->willReturnSelf();
        $redirectFactory = $this->createStub(RedirectFactory::class);
        $redirectFactory->method('create')->willReturn($this->redirect);

        $context = $this->createStub(Context::class);
        $context->method('getRequest')->willReturn($this->request);
        $context->method('getMessageManager')->willReturn($this->messages);
        $context->method('getResultRedirectFactory')->willReturn($redirectFactory);

        $this->controller = (new ObjectManager($this))->getObject(Revoke::class, [
            'context' => $context,
            'credentials' => $this->credentials,
            'customerRepository' => $this->customers,
            'notifier' => $this->notifier,
        ]);
    }

    private function withParams(int $customerId, int $entityId): void
    {
        $this->request->method('getParam')->willReturnMap([
            ['customer_id', 0, (string)$customerId],
            ['entity_id', 0, (string)$entityId],
        ]);
    }

    public function testGuardedByPasskeyAclAndPostOnly(): void
    {
        self::assertSame('DmLab_CustomerPasskey::manage', Revoke::ADMIN_RESOURCE);
        self::assertInstanceOf(HttpPostActionInterface::class, $this->controller);
    }

    public function testRevokesOwnedCredentialAndNotifies(): void
    {
        $this->withParams(42, 7);
        $credential = new Credential(entityId: 7, customerId: 42, credentialId: 'a', label: 'My phone');
        $this->credentials->expects(self::once())->method('findOwnedByCustomer')
            ->with(42, 7)->willReturn($credential);
        $customer = $this->createStub(CustomerInterface::class);
        $this->customers->method('getById')->with(42)->willReturn($customer);

        $this->credentials->expects(self::once())->method('delete')->with($credential);
        $this->notifier->expects(self::once())->method('notifyRemoved')->with($customer, 'My phone');
        $this->messages->expects(self::once())->method('addSuccessMessage');
        $this->messages->expects(self::never())->method('addErrorMessage');
        $this->redirect->expects(self::once())->method('setPath')->with('customer/index/edit', ['id' => 42]);

        self::assertSame($this->redirect, $this->controller->execute());
    }

    public function testRefusesCredentialOfAnotherCustomer(): void
    {
        $this->withParams(42, 99);
        $this->credentials->method('findOwnedByCustomer')->with(42, 99)->willReturn(null);

        $this->credentials->expects(self::never())->method('delete');
        $this->notifier->expects(self::never())->method('notifyRemoved');
        $this->messages->expects(self::once())->method('addErrorMessage');
        $this->redirect->expects(self::once())->method('setPath')->with('customer/index/edit', ['id' => 42]);

        self::assertSame($this->redirect, $this->controller->execute());
    }

    public function testRefusesWhenCustomerIsMissing(): void
    {
        $this->withParams(42, 7);
        $this->credentials->method('findOwnedByCustomer')->willReturn(new Credential(entityId: 7, customerId: 42));
        $this->customers->method('getById')->willThrowException(new NoSuchEntityException());

        $this->credentials->expects(self::never())->method('delete');
        $this->notifier->expects(self::never())->method('notifyRemoved');
        $this->messages->expects(self::once())->method('addErrorMessage');

        self::assertSame($this->redirect, $this->controller->execute());
    }

    public function testMissingCustomerIdRedirectsToGrid(): void
    {
        $this->withParams(0, 7);
        $this->credentials->method('findOwnedByCustomer')->with(0, 7)->willReturn(null);

        $this->credentials->expects(self::never())->method('delete');
        $this->messages->expects(self::once())->method('addErrorMessage');
        $this->redirect->expects(self::once())->method('setPath')->with('customer/index');

        self::assertSame($this->redirect, $this->controller->execute());
    }
}
