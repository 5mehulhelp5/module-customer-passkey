<?php
/**
 * Copyright © DMLab. All rights reserved.
 */
declare(strict_types=1);

namespace DmLab\CustomerPasskey\Test\Unit;

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

    public function testModuleXmlDeclaresSetupVersion(): void
    {
        $paths = (new ComponentRegistrar())->getPaths(ComponentRegistrar::MODULE);
        $moduleXml = ($paths['DmLab_CustomerPasskey'] ?? '') . '/etc/module.xml';

        $dom = new \DOMDocument();
        self::assertTrue($dom->load($moduleXml));

        $module = $dom->getElementsByTagName('module')->item(0);
        self::assertNotNull($module);
        self::assertSame('DmLab_CustomerPasskey', $module->getAttribute('name'));
        self::assertSame('0.0.1', $module->getAttribute('setup_version'));
    }
}
