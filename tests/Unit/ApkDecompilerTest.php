<?php

declare(strict_types=1);

namespace Sentinel\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sentinel\Tools\ApkDecompiler;
use Sentinel\Config;
use Sentinel\Exceptions\AgentException;
use Sentinel\Analyzers\AndroidManifestAnalyzer;
use SimpleXMLElement;
use ReflectionClass;
use ReflectionProperty;

/**
 * Unit tests for ApkDecompiler.
 *
 * Mocks shell execution of apktool (via partial mock on protected runCommand method)
 * to test manifest parsing, Smali extraction, error handling and integration with
 * the Tool interface without requiring a real APK or apktool binary on the test host.
 */
final class ApkDecompilerTest extends TestCase
{
    private string $tempDir;
    private string $fixtureManifestPath;

    protected function setUp(): void
    {
        $this->tempDir = sys_get_temp_dir() . '/sentinel-apk-test-' . bin2hex(random_bytes(6));
        mkdir($this->tempDir, 0777, true);

        $this->fixtureManifestPath = $this->tempDir . '/AndroidManifest.xml';
        $this->createFixtureManifest();
    }

    protected function tearDown(): void
    {
        if (is_dir($this->tempDir)) {
            $this->removeDirectory($this->tempDir);
        }
    }

    private function createFixtureManifest(): void
    {
        $xml = <<<'XML'
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="com.example.testapp"
    android:versionCode="42"
    android:versionName="2.1.0">
    <application
        android:allowBackup="true"
        android:debuggable="true"
        android:usesCleartextTraffic="false"
        android:networkSecurityConfig="@xml/network_security_config">
        <activity
            android:name=".MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        <service
            android:name=".ExportedService"
            android:exported="true"/>
    </application>
    <uses-permission android:name="android.permission.CAMERA"/>
    <uses-permission android:name="android.permission.INTERNET"/>
</manifest>
XML;

        file_put_contents($this->fixtureManifestPath, $xml);
    }

    private function removeDirectory(string $dir): void
    {
        $files = array_diff(scandir($dir) ?: ['.', '..'], ['.', '..']);
        foreach ($files as $file) {
            $path = $dir . DIRECTORY_SEPARATOR . $file;
            if (is_dir($path)) {
                $this->removeDirectory($path);
            } else {
                unlink($path);
            }
        }
        rmdir($dir);
    }

    private function createMockedDecompiler(): ApkDecompiler
    {
        $mock = $this->getMockBuilder(ApkDecompiler::class)
            ->onlyMethods(['runCommand'])
            ->setConstructorArgs([new Config()])
            ->getMock();

        // Simulate successful apktool execution without actually calling the binary
        $mock->method('runCommand')
            ->willReturnCallback(function (string $command): string {
                if (str_contains($command, 'apktool')) {
                    // Create a fake decompiled structure for subsequent calls
                    $outputDir = $this->extractOutputDirFromCommand($command);
                    if ($outputDir !== null && !file_exists($outputDir . '/AndroidManifest.xml')) {
                        mkdir($outputDir, 0777, true);
                        copy($this->fixtureManifestPath, $outputDir . '/AndroidManifest.xml');

                        // Create fake Smali structure
                        $smaliDir = $outputDir . '/smali/com/example/testapp';
                        mkdir($smaliDir, 0777, true);
                        file_put_contents(
                            $smaliDir . '/MainActivity.smali',
                            '.class public Lcom/example/testapp/MainActivity;'
                        );
                        file_put_contents(
                            $smaliDir . '/Utils.smali',
                            '.class public Lcom/example/testapp/Utils;'
                        );
                    }
                    return "I: Baksmaling... I: Decoding AndroidManifest.xml...\n";
                }
                return '';
            });

        return $mock;
    }

    private function extractOutputDirFromCommand(string $command): ?string
    {
        if (preg_match('/-o\s+([^\s]+)/', $command, $matches)) {
            return trim($matches[1], '"\'');
        }
        return null;
    }

    private function setDecompiledPath(ApkDecompiler $decompiler, string $path): void
    {
        $reflection = new ReflectionClass($decompiler);
        $property = $reflection->getProperty('decompiledPath');
        $property->setAccessible(true);
        $property->setValue($decompiler, $path);
    }

    public function testConstructorAcceptsConfigAndHasSensibleDefaults(): void
    {
        $config = new Config();
        $decompiler = new ApkDecompiler($config);

        $this->assertInstanceOf(ApkDecompiler::class, $decompiler);
    }

    public function testDecompileThrowsWhenApkFileDoesNotExist(): void
    {
        $decompiler = new ApkDecompiler();

        $this->expectException(AgentException::class);
        $this->expectExceptionMessage('APK file not found');

        $decompiler->decompile($this->tempDir . '/nonexistent.apk');
    }

    public function testDecompileRunsApktoolAndSetsInternalPath(): void
    {
        $decompiler = $this->createMockedDecompiler();
        $fakeApk = $this->tempDir . '/test.apk';
        touch($fakeApk);

        $outputPath = $decompiler->decompile($fakeApk);

        $this->assertStringContainsString('sentinel-decompiled', $outputPath);
        $this->assertDirectoryExists($outputPath);
        $this->assertFileExists($outputPath . '/AndroidManifest.xml');
    }

    public function testGetManifestThrowsIfDecompileNotCalledFirst(): void
    {
        $decompiler = new ApkDecompiler();

        $this->expectException(AgentException::class);
        $this->expectExceptionMessage('Must call decompile() before accessing manifest');

        $decompiler->getManifest();
    }

    public function testGetManifestReturnsParsedSimpleXMLElementWithCorrectValues(): void
    {
        $decompiler = $this->createMockedDecompiler();
        $fakeApk = $this->tempDir . '/test.apk';
        touch($fakeApk);

        $decompiler->decompile($fakeApk);
        $manifest = $decompiler->getManifest();

        $this->assertInstanceOf(SimpleXMLElement::class, $manifest);
        $this->assertSame('com.example.testapp', (string) $manifest['package']);
        $this->assertSame('42', (string) $manifest['versionCode']);
        $this->assertSame('2.1.0', (string) $manifest['versionName']);

        // Verify namespace registration works for Android attributes
        $manifest->registerXPathNamespace('android', 'http://schemas.android.com/apk/res/android');
        $debuggable = $manifest->xpath('//android:application/@android:debuggable');
        $this->assertNotEmpty($debuggable);
        $this->assertSame('true', (string) $debuggable[0]);
    }

    public function testExtractSmaliClassesReturnsNormalizedClassNames(): void
    {
        $decompiler = $this->createMockedDecompiler();
        $fakeApk = $this->tempDir . '/test.apk';
        touch($fakeApk);

        $decompiler->decompile($fakeApk);
        $classes = $decompiler->extractSmaliClasses();

        $this->assertIsArray($classes);
        $this->assertCount(2, $classes);
        $this->assertContains('com.example.testapp.MainActivity', $classes);
        $this->assertContains('com.example.testapp.Utils', $classes);
    }

    public function testExtractSmaliClassesReturnsEmptyArrayWhenNoSmaliDirectory(): void
    {
        $decompiler = $this->createMockedDecompiler();
        $fakeApk = $this->tempDir . '/test.apk';
        touch($fakeApk);

        // Force a decompiled path without smali
        $emptyPath = $this->tempDir . '/empty-decompile';
        mkdir($emptyPath, 0777, true);
        $this->setDecompiledPath($decompiler, $emptyPath);

        $classes = $decompiler->extractSmaliClasses();

        $this->assertIsArray($classes);
        $this->assertEmpty($classes);
    }

    public function testExecuteImplementsToolInterfaceAndReturnsStructuredResult(): void
    {
        $decompiler = $this->createMockedDecompiler();
        $fakeApk = $this->tempDir . '/test.apk';
        touch($fakeApk);

        $result = $decompiler->execute(['target' => $fakeApk]);

        $this->assertIsArray($result);
        $this->assertArrayHasKey('manifest', $result);
        $this->assertArrayHasKey('smali_classes', $result);
        $this->assertArrayHasKey('output_path', $result);
        $this->assertInstanceOf(SimpleXMLElement::class, $result['manifest']);
        $this->assertIsArray($result['smali_classes']);
        $this->assertStringContainsString('sentinel-decompiled', $result['output_path']);
    }

    public function testGetDescriptionReturnsHumanReadableToolDescription(): void
    {
        $decompiler = new ApkDecompiler();

        $description = $decompiler->getDescription();

        $this->assertIsString($description);
        $this->assertStringContainsString('Decompiles', $description);
        $this->assertStringContainsString('apktool', strtolower($description));
        $this->assertStringContainsString('manifest', strtolower($description));
        $this->assertStringContainsString('Smali', $description);
    }

    public function testDecompileWithCustomOutputDirectoryFromConfig(): void
    {
        $customConfig = new class extends Config {
            public function getToolConfig(string $toolName = ''): array
            {
                if ($toolName === 'apk_decompiler') {
                    return [
                        'apktool_binary' => 'apktool',
                        'output_dir' => '/tmp/custom-sentinel-output',
                    ];
                }
                return parent::getToolConfig($toolName);
            }
        };

        $decompiler = new ApkDecompiler($customConfig);
        $fakeApk = $this->tempDir . '/test.apk';
        touch($fakeApk);

        $outputPath = $decompiler->decompile($fakeApk);

        $this->assertStringContainsString('custom-sentinel-output', $outputPath);
    }

    public function testAnalyzeManifestViaIntegrationWithAndroidManifestAnalyzer(): void
    {
        $decompiler = $this->createMockedDecompiler();
        $fakeApk = $this->tempDir . '/test.apk';
        touch($fakeApk);

        $decompiler->decompile($fakeApk);
        $manifest = $decompiler->getManifest();

        $analyzer = new AndroidManifestAnalyzer();
        $reports = $analyzer->analyze($manifest);

        $this->assertIsArray($reports);
        $this->assertNotEmpty($reports);

        $titles = array_map(static fn($report) => $report->getTitle(), $reports);

        // Manifest fixture should trigger debuggable and dangerous permission findings
        $this->assertContains('Debuggable Application', $titles);
        $this->assertContains('Dangerous Permissions Declared', $titles);
        $this->assertContains('Exported Activity Without Protection', $titles);
    }
}
