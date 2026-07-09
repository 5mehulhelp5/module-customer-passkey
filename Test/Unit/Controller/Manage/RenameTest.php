<?php
/**
 * Copyright © MageDevGroup. All rights reserved.
 */
declare(strict_types=1);

namespace MageDevGroup\CustomerPasskey\Test\Unit\Controller\Manage;

use MageDevGroup\CustomerPasskey\Controller\Manage\Rename;
use MageDevGroup\CustomerPasskey\Model\Credential;
use MageDevGroup\CustomerPasskey\Model\CredentialRepository;
use Magento\Customer\Model\Session;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[AllowMockObjectsWithoutExpectations]
class RenameTest extends TestCase
{
    /** @var Session&MockObject */
    private $session;

    /** @var RequestInterface&MockObject */
    private $request;

    /** @var CredentialRepository&MockObject */
    private $credentials;

    /** @var Json&MockObject */
    private $json;

    /** @var Rename */
    private Rename $controller;

    protected function setUp(): void
    {
        $this->session = $this->createMock(Session::class);
        $this->request = $this->createMock(RequestInterface::class);
        $this->credentials = $this->createMock(CredentialRepository::class);

        $this->json = $this->createMock(Json::class);
        $this->json->method('setHttpResponseCode')->willReturnSelf();
        $this->json->method('setData')->willReturnSelf();

        $jsonFactory = $this->createStub(JsonFactory::class);
        $jsonFactory->method('create')->willReturn($this->json);

        $this->controller = new Rename($this->session, $this->request, $this->credentials, $jsonFactory);
    }

    private function loginAs(int $customerId = 42): void
    {
        $this->session->method('isLoggedIn')->willReturn(true);
        $this->session->method('getCustomerId')->willReturn($customerId);
    }

    private function params(int $entityId, string $label): void
    {
        $this->request->method('getParam')->willReturnMap([
            ['entity_id', 0, (string)$entityId],
            ['label', '', $label],
        ]);
    }

    public function testRefusesAnonymousRequest(): void
    {
        $this->session->method('isLoggedIn')->willReturn(false);

        $this->credentials->expects(self::never())->method('findOwnedByCustomer');
        $this->credentials->expects(self::never())->method('save');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(403);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testRejectsCredentialNotOwnedByCustomer(): void
    {
        $this->loginAs();
        $this->params(99, 'Hacked');
        $this->credentials->expects(self::once())->method('findOwnedByCustomer')
            ->with(42, 99)->willReturn(null);

        $this->credentials->expects(self::never())->method('save');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(404);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testRenamesOwnedCredential(): void
    {
        $this->loginAs();
        $this->params(7, ' My laptop ');
        $credential = new Credential(entityId: 7, customerId: 42, credentialId: 'a', label: 'Old');
        $this->credentials->method('findOwnedByCustomer')->with(42, 7)->willReturn($credential);

        $this->credentials->expects(self::once())->method('save')
            ->with(self::callback(static fn(Credential $c): bool => $c->label === 'My laptop'));
        $this->json->expects(self::never())->method('setHttpResponseCode');
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === true));

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testBlankLabelClearsIt(): void
    {
        $this->loginAs();
        $this->params(7, '   ');
        $credential = new Credential(entityId: 7, customerId: 42, credentialId: 'a', label: 'Old');
        $this->credentials->method('findOwnedByCustomer')->willReturn($credential);

        $this->credentials->expects(self::once())->method('save')
            ->with(self::callback(static fn(Credential $c): bool => $c->label === null));

        self::assertSame($this->json, $this->controller->execute());
    }
}
