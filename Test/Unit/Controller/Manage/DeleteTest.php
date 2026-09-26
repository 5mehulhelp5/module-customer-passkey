<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit\Controller\Manage;

use DmLab\CustomerPasskey\Controller\Manage\Delete;
use DmLab\CustomerPasskey\Model\Credential;
use DmLab\CustomerPasskey\Model\CredentialRepository;
use Magento\Customer\Model\Session;
use Magento\Framework\App\RequestInterface;
use Magento\Framework\Controller\Result\Json;
use Magento\Framework\Controller\Result\JsonFactory;
use PHPUnit\Framework\Attributes\AllowMockObjectsWithoutExpectations;
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;

#[AllowMockObjectsWithoutExpectations]
class DeleteTest extends TestCase
{
    /** @var Session&MockObject */
    private $session;

    /** @var RequestInterface&MockObject */
    private $request;

    /** @var CredentialRepository&MockObject */
    private $credentials;

    /** @var Json&MockObject */
    private $json;

    /** @var Delete */
    private Delete $controller;

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

        $this->controller = new Delete($this->session, $this->request, $this->credentials, $jsonFactory);
    }

    private function loginAs(int $customerId = 42): void
    {
        $this->session->method('isLoggedIn')->willReturn(true);
        $this->session->method('getCustomerId')->willReturn($customerId);
    }

    private function withEntityId(int $entityId): void
    {
        $this->request->method('getParam')->willReturnMap([
            ['entity_id', 0, (string)$entityId],
        ]);
    }

    public function testRefusesAnonymousRequest(): void
    {
        $this->session->method('isLoggedIn')->willReturn(false);

        $this->credentials->expects(self::never())->method('findOwnedByCustomer');
        $this->credentials->expects(self::never())->method('delete');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(403);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testRejectsCredentialNotOwnedByCustomer(): void
    {
        $this->loginAs();
        $this->withEntityId(99);
        $this->credentials->expects(self::once())->method('findOwnedByCustomer')
            ->with(42, 99)->willReturn(null);

        $this->credentials->expects(self::never())->method('delete');
        $this->json->expects(self::once())->method('setHttpResponseCode')->with(404);

        self::assertSame($this->json, $this->controller->execute());
    }

    public function testDeletesOwnedCredential(): void
    {
        $this->loginAs();
        $this->withEntityId(7);
        $credential = new Credential(entityId: 7, customerId: 42, credentialId: 'a');
        $this->credentials->method('findOwnedByCustomer')->with(42, 7)->willReturn($credential);

        $this->credentials->expects(self::once())->method('delete')->with($credential);
        $this->json->expects(self::never())->method('setHttpResponseCode');
        $this->json->expects(self::once())->method('setData')
            ->with(self::callback(static fn(array $d): bool => $d['success'] === true));

        self::assertSame($this->json, $this->controller->execute());
    }
}
