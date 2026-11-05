<?php

declare(strict_types=1);

namespace Sentinel\Commands;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Sentinel\Config;
use Sentinel\Exceptions\AgentException;
use RuntimeException;

/**
 * Initializes a new sentinel.json configuration file.
 *
 * Creates a ready-to-use config with a placeholder for the LLM API key
 * and sensible defaults for tools, security thresholds and reporting.
 * Warns before overwriting an existing file and provides next-step guidance.
 */
final class InitCommand extends Command
{
    public function __construct(
        private readonly Config $config
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setName('init')
            ->setDescription('Create a default sentinel.json configuration file with API key placeholders')
            ->setHelp(
                'Generates a starter sentinel.json containing default LLM settings, ' .
                'tool parameters, security thresholds and a placeholder for your OpenAI API key.'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('Sentinel AI - Initialize Configuration');
        $io->writeln('<fg=gray>Creating a secure default configuration...</>');
        $io->newLine();

        $configPath = $this->config->getConfigPath();

        if (file_exists($configPath)) {
            $io->warning(sprintf('Configuration file "%s" already exists.', $configPath));
            if (!$io->confirm('Overwrite the existing file?', false)) {
                $io->info('Operation cancelled. Existing configuration was left untouched.');
                return Command::SUCCESS;
            }
        }

        try {
            $this->writeDefaultConfig($configPath);

            $io->success([
                sprintf('Successfully created "%s"', $configPath),
                '',
                'Next steps:',
                '  1. Replace "sk-your-openai-api-key-here" with a real key (or set OPENAI_API_KEY env var)',
                '  2. Review tool and security settings',
                '  3. Run: <fg=cyan>php bin/sentinel audit --target=app.apk --type=android</>',
            ]);

            $io->note([
                'Never commit real API keys to version control.',
                'The file has been created with restrictive permissions (0600).',
            ]);

            return Command::SUCCESS;
        } catch (RuntimeException|AgentException $e) {
            $io->error('Failed to create configuration: ' . $e->getMessage());
            return Command::FAILURE;
        }
    }

    /**
     * Writes a default configuration augmented with an API key placeholder.
     *
     * @throws RuntimeException If the file cannot be written
     */
    private function writeDefaultConfig(string $path): void
    {
        $baseConfig = $this->config->all();

        // Ensure LLM section has an explicit placeholder (the default Config
        // relies on environment variables; we surface it here for clarity).
        if (!isset($baseConfig['llm']['api_key']) || trim((string) $baseConfig['llm']['api_key']) === '') {
            $baseConfig['llm']['api_key'] = 'sk-your-openai-api-key-here-replace-this';
        }

        $json = json_encode($baseConfig, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        if (file_put_contents($path, $json) === false) {
            throw new RuntimeException(sprintf(
                'Unable to write configuration to "%s". Check directory permissions.',
                $path
            ));
        }

        // Secure permissions - only owner can read/write (API key inside)
        if (function_exists('chmod')) {
            @chmod($path, 0600);
        }
    }
}
