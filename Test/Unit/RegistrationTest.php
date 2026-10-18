<?php
/**
 * Copyright © DMLab. All rights reserved.
 * Licensed under the Open Software License version 3.0 (OSL-3.0). See LICENSE.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit;

use DmLab\CustomerPasskey\Controller\Adminhtml\Customer\Revoke;
use DmLab\CustomerPasskey\Model\Config;
use Magento\Framework\Component\ComponentRegistrar;
use PHPUnit\Framework\TestCase;

class RegistrationTest extends TestCase
{
    public function testModuleIsRegistered(): void
    {
        $paths = (new ComponentRegistrar())->getPaths(ComponentRegistrar::MODULE);

        self::assertArrayHasKey('DmLab_CustomerPasskey', $paths);
    }

    public function testRegisteredPathPointsAtThisModule(): void
    {
        $paths = (new ComponentRegistrar())->getPaths(ComponentRegistrar::MODULE);
        $path = $paths['DmLab_CustomerPasskey'] ?? null;

        self::assertNotNull($path);
        self::assertDirectoryExists($path);
        self::assertFileExists($path . '/etc/module.xml');
    }

    public function testModuleXmlDeclaresModuleWithoutSetupVersion(): void
    {
        $module = $this->loadModuleXml()->documentElement->getElementsByTagName('module')->item(0);

        self::assertNotNull($module);
        self::assertSame('DmLab_CustomerPasskey', $module->getAttribute('name'));
        self::assertFalse($module->hasAttribute('setup_version'));
    }

    public function testModuleXmlSequencesMagentoDependencies(): void
    {
        $xpath = new \DOMXPath($this->loadModuleXml());
        $sequenced = [];
        foreach ($xpath->query('/config/module[@name="DmLab_CustomerPasskey"]/sequence/module') as $node) {
            $sequenced[] = $node->getAttribute('name');
        }

        self::assertSame(
            ['Magento_Customer', 'Magento_Store', 'Magento_Config', 'Magento_Backend', 'Magento_Ui', 'Magento_Email'],
            $sequenced
        );
    }

    public function testDefaultEmailTemplatesAreDeclaredWithExistingFiles(): void
    {
        $xpath = new \DOMXPath($this->loadXml('etc/email_templates.xml'));
        $configXpath = new \DOMXPath($this->loadXml('etc/config.xml'));

        foreach (['added_template', 'removed_template'] as $field) {
            $default = $configXpath->query("/config/default/dmlab_customer_passkey/notification/$field")
                ->item(0)?->textContent;
            $template = $xpath->query(sprintf('/config/template[@id="%s"]', $default))->item(0);

            self::assertInstanceOf(\DOMElement::class, $template, $field);
            self::assertFileExists($this->modulePath() . '/view/frontend/email/' . $template->getAttribute('file'));
        }
        self::assertSame(Config::DEFAULT_ADDED_TEMPLATE, $xpath->query('/config/template/@id')->item(0)->nodeValue);
        self::assertSame(Config::DEFAULT_REMOVED_TEMPLATE, $xpath->query('/config/template/@id')->item(1)->nodeValue);
    }

    public function testAclDeclaresRevokeResource(): void
    {
        $xpath = new \DOMXPath($this->loadXml('etc/acl.xml'));

        self::assertSame(1, $xpath->query(sprintf('//resource[@id="%s"]', Revoke::ADMIN_RESOURCE))->length);
    }

    private function loadModuleXml(): \DOMDocument
    {
        return $this->loadXml('etc/module.xml');
    }

    private function loadXml(string $file): \DOMDocument
    {
        $dom = new \DOMDocument();
        self::assertTrue($dom->load($this->modulePath() . '/' . $file));

        return $dom;
    }

    private function modulePath(): string
    {
        return (new ComponentRegistrar())->getPaths(ComponentRegistrar::MODULE)['DmLab_CustomerPasskey'] ?? '';
    }
}
