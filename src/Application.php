<?php

declare(strict_types=1);

namespace Sentinel;

use Symfony\Component\Console\Application as SymfonyApplication;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Sentinel\Config;
use Sentinel\Commands\AuditCommand;
use Sentinel\Commands\InitCommand;
use Sentinel\Tools\ToolRegistry;
use Sentinel\Tools\ApkDecompiler;
use Sentinel\Tools\WebVulnScanner;
use Sentinel\LLM\LLMInterface;
use Sentinel\LLM\OpenAIClient;
use Sentinel\Agent\AgentFactory;
use Sentinel\Reporters\ReportGenerator;

/**
 * Main entry point for the Sentinel AI CLI.
 *
 * Bootstraps the service container (simple service wiring), registers
 * ToolRegistry with core tools, configures the LLM client, and registers
 * all Symfony Console commands.
 */
final class Application extends SymfonyApplication
{
    private Config $config;
    private ToolRegistry $toolRegistry;
    private LLMInterface $llm;

    public function __construct(string $name = 'Sentinel AI', string $version = '1.0.0')
    {
        parent::__construct($name, $version);

        $this->config = new Config();
        $this->toolRegistry = new ToolRegistry();
        $this->llm = $this->createLLMClient();

        $this->registerDefaultTools();
        $this->registerCommands();

        $this->setName('Sentinel AI');
        $this->setVersion($version);
    }

    private function createLLMClient(): LLMInterface
    {
        $llmConfig = $this->config->getLLMConfig();

        $apiKey = $llmConfig['api_key']
            ?? getenv('OPENAI_API_KEY')
            ?? getenv('LLM_API_KEY')
            ?? '';

        $model = $llmConfig['model'] ?? 'gpt-4o-mini';
        $baseUri = $llmConfig['base_uri'] ?? null;

        return new OpenAIClient($apiKey, $model, $baseUri);
    }

    private function registerDefaultTools(): void
    {
        $this->toolRegistry->register('apk-decompiler', new ApkDecompiler());
        $this->toolRegistry->register('web-vuln-scanner', new WebVulnScanner());

        // Additional tools can be registered via config or extension points
    }

    private function registerCommands(): void
    {
        $agentFactory = new AgentFactory(
            $this->config,
            $this->toolRegistry,
            $this->llm
        );

        $reportGenerator = new ReportGenerator();

        $this->add(new InitCommand($this->config));
        $this->add(new AuditCommand(
            $agentFactory,
            $reportGenerator,
            $this->config,
            $this->toolRegistry
        ));
    }

    /**
     * Returns the active configuration.
     */
    public function getConfig(): Config
    {
        return $this->config;
    }

    /**
     * Returns the tool registry.
     */
    public function getToolRegistry(): ToolRegistry
    {
        return $this->toolRegistry;
    }

    /**
     * Returns the configured LLM client.
     */
    public function getLLM(): LLMInterface
    {
        return $this->llm;
    }

    public function run(InputInterface $input = null, OutputInterface $output = null): int
    {
        if ($output !== null) {
            $output->writeln('<fg=cyan;options=bold>Sentinel AI</>');
            $output->writeln('<fg=gray>Autonomous APK & Web Security Auditor (LLM + Apktool)</>');
            $output->writeln('');
        }

        return parent::run($input, $output);
    }
}
