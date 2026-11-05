<?php

declare(strict_types=1);

namespace Sentinel\Tools;

use Sentinel\Config;
use Sentinel\Exceptions\AgentException;
use RuntimeException;
use SimpleXMLElement;

/**
 * Tool that wraps Apktool to decompile Android APKs.
 *
 * Uses proc_open (no shell_exec) for secure command execution.
 * Provides manifest parsing via SimpleXMLElement and Smali extraction.
 * Constructor accepts optional Config to reconcile different instantiation
 * sites (Application.php vs SecurityAgent.php).
 */
final class ApkDecompiler implements Tool
{
    private ?string $decompiledPath = null;
    private ?SimpleXMLElement $manifest = null;
    private string $outputDir;
    private string $apktoolBinary;

    /**
     * @param Config|null $config If omitted, sensible defaults are used (makes
     *                            both Application.php and SecurityAgent.php happy).
     */
    public function __construct(?Config $config = null)
    {
        $toolConfig = $config?->getToolConfig('apk_decompiler') ?? [];

        $this->outputDir = $toolConfig['output_dir'] ?? './sentinel-decompiled';
        $this->apktoolBinary = $toolConfig['apktool_binary'] ?? 'apktool';

        $this->ensureOutputDirectoryExists();
        $this->ensureApktoolAvailable();
    }

    public function getDescription(): string
    {
        return 'Decompiles an APK using Apktool, extracts AndroidManifest.xml as SimpleXMLElement and provides access to Smali classes for static analysis.';
    }

    /**
     * Implements the Tool contract. Accepts a target APK path.
     *
     * @param array<string, mixed> $parameters
     * @throws AgentException
     */
    public function execute(array $parameters = []): string
    {
        $target = $parameters['target'] ?? ($parameters[0] ?? null);

        if (!is_string($target) || trim($target) === '') {
            throw new AgentException('ApkDecompiler requires a valid "target" APK path in parameters.');
        }

        $this->decompile($target);

        $smaliCount = count($this->extractSmaliClasses());

        return sprintf(
            'Successfully decompiled APK to %s. Manifest parsed. %d Smali files extracted and ready for analysis.',
            $this->decompiledPath,
            $smaliCount
        );
    }

    /**
     * Decompiles the given APK and stores internal state.
     *
     * @return string Path to the decompiled directory
     * @throws AgentException
     */
    public function decompile(string $path): string
    {
        if (!file_exists($path)) {
            throw new AgentException(sprintf('APK file does not exist: %s', $path));
        }

        if (!str_ends_with(strtolower($path), '.apk')) {
            throw new AgentException(sprintf('Target "%s" does not appear to be an APK (must end with .apk).', $path));
        }

        $baseName = basename($path, '.apk');
        $outputPath = rtrim($this->outputDir, DIRECTORY_SEPARATOR) . DIRECTORY_SEPARATOR . $baseName;

        if (is_dir($outputPath)) {
            $this->recursiveDelete($outputPath);
        }

        $command = [
            $this->apktoolBinary,
            'd',
            $path,
            '--output',
            $outputPath,
            '--force',
        ];

        $this->runCommand($command);

        $this->decompiledPath = $outputPath;

        $manifestPath = $outputPath . DIRECTORY_SEPARATOR . 'AndroidManifest.xml';
        if (!file_exists($manifestPath)) {
            throw new AgentException('AndroidManifest.xml not found after decompilation.');
        }

        $xmlContent = file_get_contents($manifestPath);
        if ($xmlContent === false) {
            throw new AgentException('Failed to read AndroidManifest.xml.');
        }

        try {
            $this->manifest = new SimpleXMLElement($xmlContent, LIBXML_NONET | LIBXML_NOERROR | LIBXML_NOWARNING);
        } catch (\Throwable $e) {
            throw new AgentException('Failed to parse AndroidManifest.xml: ' . $e->getMessage(), 0, $e);
        }

        return $outputPath;
    }

    /**
     * Returns the parsed manifest.
     *
     * @throws AgentException if decompile() has not been called
     */
    public function getManifest(): SimpleXMLElement
    {
        if ($this->manifest === null) {
            throw new AgentException('Manifest not available. Call decompile($path) first.');
        }

        return $this->manifest;
    }

    /**
     * Returns list of all discovered Smali class files.
     *
     * @return list<string> Full paths to .smali files
     * @throws AgentException
     */
    public function extractSmaliClasses(): array
    {
        if ($this->decompiledPath === null || !is_dir($this->decompiledPath)) {
            throw new AgentException('No decompiled application available. Call decompile() first.');
        }

        $smaliDir = $this->decompiledPath . DIRECTORY_SEPARATOR . 'smali';
        if (!is_dir($smaliDir)) {
            return [];
        }

        $smaliFiles = [];
        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($smaliDir, \RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $file->getExtension() === 'smali') {
                $smaliFiles[] = $file->getPathname();
            }
        }

        return $smaliFiles;
    }

    private function ensureOutputDirectoryExists(): void
    {
        if (is_dir($this->outputDir)) {
            return;
        }

        if (!mkdir($this->outputDir, 0755, true) && !is_dir($this->outputDir)) {
            throw new RuntimeException(sprintf('Could not create output directory "%s". Check permissions.', $this->outputDir));
        }
    }

    private function ensureApktoolAvailable(): void
    {
        $command = [$this->apktoolBinary, '--version'];

        $descriptorspec = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = proc_open($command, $descriptorspec, $pipes);

        if (!is_resource($process)) {
            throw new AgentException('Could not launch apktool. Is it installed and in your PATH?');
        }

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);
        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        proc_close($process);

        if (trim($stdout) === '' && trim($stderr) !== '') {
            throw new AgentException(
                'Apktool is not available or not executable. ' .
                'Install it from https://ibotpeaches.github.io/Apktool/ and ensure "' .
                $this->apktoolBinary . '" is in your PATH.'
            );
        }
    }

    /**
     * Runs a command via proc_open (prevents shell injection).
     *
     * @param list<string> $command
     * @throws AgentException
     */
    private function runCommand(array $command): void
    {
        $descriptorspec = [
            0 => ['pipe', 'r'],
            1 => ['pipe', 'w'],
            2 => ['pipe', 'w'],
        ];

        $process = proc_open($command, $descriptorspec, $pipes, null, null);

        if (!is_resource($process)) {
            throw new AgentException('Failed to launch apktool process.');
        }

        $stdout = stream_get_contents($pipes[1]);
        $stderr = stream_get_contents($pipes[2]);

        fclose($pipes[0]);
        fclose($pipes[1]);
        fclose($pipes[2]);

        $returnCode = proc_close($process);

        if ($returnCode !== 0) {
            $error = trim($stderr ?: $stdout ?: 'Unknown error');
            throw new AgentException(sprintf(
                'Apktool failed with exit code %d: %s',
                $returnCode,
                $error
            ));
        }
    }

    private function recursiveDelete(string $directory): void
    {
        if (!is_dir($directory)) {
            return;
        }

        $iterator = new \RecursiveIteratorIterator(
            new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS),
            \RecursiveIteratorIterator::CHILD_FIRST
        );

        foreach ($iterator as $file) {
            if ($file->isDir()) {
                @rmdir($file->getPathname());
            } else {
                @unlink($file->getPathname());
            }
        }

        @rmdir($directory);
    }
}
