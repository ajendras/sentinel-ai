<?php

declare(strict_types=1);

namespace Sentinel;

use JsonException;
use RuntimeException;

/**
 * Manages loading, validation and access to sentinel.json configuration.
 *
 * Supports LLM settings, tool parameters and security thresholds.
 * Falls back to sensible defaults when the config file is missing.
 * API keys can be provided via config or environment variables.
 */
final class Config
{
    private const DEFAULT_CONFIG_PATH = 'sentinel.json';

    private array $config;
    private string $configPath;

    public function __construct(string $configPath = self::DEFAULT_CONFIG_PATH)
    {
        $this->configPath = $configPath;
        $this->loadConfig();
    }

    private function loadConfig(): void
    {
        if (!file_exists($this->configPath)) {
            $this->config = $this->getDefaultConfig();
            return;
        }

        $content = file_get_contents($this->configPath);
        if ($content === false) {
            throw new RuntimeException(sprintf(
                'Unable to read configuration file "%s". Check file permissions.',
                $this->configPath
            ));
        }

        try {
            $decoded = json_decode($content, true, 512, JSON_THROW_ON_ERROR);
            if (!is_array($decoded)) {
                throw new RuntimeException('Configuration root must be a JSON object.');
            }
            $this->config = $decoded;
        } catch (JsonException $e) {
            throw new RuntimeException(
                sprintf('Invalid JSON in "%s": %s', $this->configPath, $e->getMessage()),
                0,
                $e
            );
        }

        $this->validate();
    }

    private function getDefaultConfig(): array
    {
        return [
            'llm' => [
                'model' => 'gpt-4o-mini',
                'temperature' => 0.0,
                'max_tokens' => 2048,
                'base_uri' => null,
            ],
            'tools' => [
                'max_steps' => 12,
                'apk_decompiler' => [
                    'apktool_binary' => 'apktool',
                    'framework_dir' => null,
                    'output_dir' => './sentinel-decompiled',
                ],
                'web_scanner' => [
                    'timeout' => 10,
                    'user_agent' => 'Sentinel-AI/1.0',
                    'max_crawl_depth' => 3,
                ],
            ],
            'security' => [
                'confidence_threshold' => 65,
                'include_low_severity' => false,
            ],
            'report' => [
                'output_dir' => './sentinel-reports',
                'include_html' => true,
            ],
        ];
    }

    private function validate(): void
    {
        if (!isset($this->config['llm']) || !is_array($this->config['llm'])) {
            throw new RuntimeException('Configuration must contain an "llm" section (array).');
        }

        $llm = $this->config['llm'];

        if (empty($llm['model'])) {
            throw new RuntimeException('LLM "model" must be specified in configuration.');
        }

        if (isset($llm['temperature']) && (!is_numeric($llm['temperature']) || $llm['temperature'] < 0 || $llm['temperature'] > 2)) {
            throw new RuntimeException('LLM "temperature" must be a number between 0 and 2.');
        }

        if (!isset($this->config['tools']) || !is_array($this->config['tools'])) {
            throw new RuntimeException('Configuration must contain a "tools" section (array).');
        }

        if (!isset($this->config['security']) || !is_array($this->config['security'])) {
            throw new RuntimeException('Configuration must contain a "security" section (array).');
        }
    }

    /**
     * Returns LLM configuration with environment variable fallbacks for credentials.
     *
     * @return array<string, mixed>
     */
    public function getLLMConfig(): array
    {
        $llm = $this->config['llm'] ?? [];

        $apiKey = $llm['api_key']
            ?? getenv('OPENAI_API_KEY')
            ?? getenv('LLM_API_KEY')
            ?? null;

        if ($apiKey !== null) {
            $llm['api_key'] = $apiKey;
        }

        return $llm;
    }

    /**
     * Returns configuration for a specific tool or all tools if no name given.
     *
     * @return array<string, mixed>
     */
    public function getToolConfig(string $toolName = ''): array
    {
        $tools = $this->config['tools'] ?? [];

        if ($toolName === '') {
            return $tools;
        }

        return $tools[$toolName] ?? [];
    }

    /**
     * Returns security-specific configuration.
     *
     * @return array<string, mixed>
     */
    public function getSecurityConfig(): array
    {
        return $this->config['security'] ?? [];
    }

    /**
     * Returns the complete configuration array (for debugging/serialization).
     *
     * @return array<string, mixed>
     */
    public function all(): array
    {
        return $this->config;
    }

    /**
     * Persists the current configuration back to disk as JSON.
     */
    public function save(): void
    {
        $json = json_encode($this->config, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        if (file_put_contents($this->configPath, $json) === false) {
            throw new RuntimeException(sprintf(
                'Failed to write configuration to "%s". Check directory permissions.',
                $this->configPath
            ));
        }
    }

    /**
     * Returns path to the configuration file.
     */
    public function getConfigPath(): string
    {
        return $this->configPath;
    }
}
