<?php

declare(strict_types=1);

namespace Sentinel\Commands;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Style\SymfonyStyle;
use Sentinel\Agent\AgentFactory;
use Sentinel\Reporters\ReportGenerator;
use Sentinel\Reporters\Report;
use Sentinel\Config;
use Sentinel\Tools\ToolRegistry;
use Sentinel\Exceptions\AgentException;
use RuntimeException;

/**
 * Symfony Console command that drives the full autonomous security audit.
 *
 * Handles CLI flags (--target, --type, --interactive, --model, --output),
 * orchestrates the AgentFactory + SecurityAgent, runs the reasoning loop,
 * and delegates output generation to ReportGenerator.
 */
final class AuditCommand extends Command
{
    public function __construct(
        private readonly AgentFactory $agentFactory,
        private readonly ReportGenerator $reportGenerator,
        private readonly Config $config,
        private readonly ToolRegistry $toolRegistry
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this
            ->setName('audit')
            ->setDescription('Run an autonomous security audit on an Android APK or web application')
            ->setHelp('Performs LLM-driven analysis using Apktool for Android or HTTP crawling for web targets.')
            ->addOption(
                'target',
                't',
                InputOption::VALUE_REQUIRED,
                'Path to APK file or base URL of the web application'
            )
            ->addOption(
                'type',
                null,
                InputOption::VALUE_OPTIONAL,
                'Audit type: android or web',
                'android'
            )
            ->addOption(
                'interactive',
                'i',
                InputOption::VALUE_NONE,
                'Launch interactive explorer after the audit completes'
            )
            ->addOption(
                'model',
                'm',
                InputOption::VALUE_OPTIONAL,
                'Override the LLM model (e.g. gpt-4o)'
            )
            ->addOption(
                'output',
                'o',
                InputOption::VALUE_OPTIONAL,
                'Directory where JSON and HTML reports will be saved'
            );
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $io->title('Sentinel AI');
        $io->writeln('<fg=gray>Autonomous APK & Web Security Auditor (LLM + Apktool)</>');
        $io->newLine();

        $target = (string) $input->getOption('target');
        if ($target === '') {
            $io->error('The --target option is required. Provide an APK path or a web URL.');
            return Command::INVALID;
        }

        $type = strtolower((string) $input->getOption('type'));
        if (!in_array($type, ['android', 'web'], true)) {
            $io->error('Type must be "android" or "web".');
            return Command::INVALID;
        }

        $modelOverride = (string) $input->getOption('model');
        if ($modelOverride !== '') {
            $io->note(sprintf('Model override "%s" requested. Currently the LLM is configured at Application boot.', $modelOverride));
        }

        $outputDir = (string) ($input->getOption('output') ?: $this->config->all()['report']['output_dir'] ?? './sentinel-reports');

        try {
            $io->info(sprintf('Starting %s security audit of <fg=white>%s</>', $type, $target));

            $agent = $this->agentFactory->create($type);
            $reports = $agent->audit($target, $type);

            $this->reportGenerator->generateConsole($reports, $io);

            if (!is_dir($outputDir) && !mkdir($outputDir, 0755, true) && !is_dir($outputDir)) {
                throw new RuntimeException(sprintf('Unable to create output directory "%s".', $outputDir));
            }

            $timestamp = date('Ymd-His');
            $basePath = rtrim($outputDir, '/') . '/audit-' . $timestamp;

            $jsonPath = $basePath . '.json';
            $htmlPath = $basePath . '.html';

            $this->reportGenerator->saveJson($reports, $jsonPath);
            $this->reportGenerator->saveHtml($reports, $htmlPath);

            $io->success([
                'Audit completed successfully!',
                '',
                sprintf('JSON report: %s', $jsonPath),
                sprintf('HTML report: %s', $htmlPath),
            ]);

            if ($input->getOption('interactive')) {
                $this->runInteractiveMode($reports, $io);
            }

            return Command::SUCCESS;
        } catch (AgentException $e) {
            $io->error($e->getMessage());
            if ($e->getPrevious() !== null) {
                $io->writeln('<fg=gray>' . $e->getPrevious()->getMessage() . '</>');
            }
            return Command::FAILURE;
        } catch (RuntimeException $e) {
            $io->error($e->getMessage());
            return Command::FAILURE;
        } catch (\Throwable $e) {
            $io->error('Unexpected error during audit: ' . $e->getMessage());
            return Command::FAILURE;
        }
    }

    /**
     * Provides an interactive terminal UI for exploring individual findings.
     *
     * @param Report[] $reports
     */
    private function runInteractiveMode(array $reports, SymfonyStyle $io): void
    {
        $validReports = array_values(array_filter($reports, static fn($r): bool => $r instanceof Report));

        if (empty($validReports)) {
            $io->warning('No findings available to explore.');
            return;
        }

        $io->newLine(2);
        $io->section('🔎 Interactive Findings Explorer');
        $io->writeln('Select a finding below to see full evidence and remediation details.');
        $io->newLine();

        $choices = [];
        foreach ($validReports as $index => $report) {
            $choices[$index + 1] = sprintf(
                '%s <fg=%s>%s</> %s',
                $this->severityEmoji($report->getSeverity()),
                $this->severityColor($report->getSeverity()),
                strtoupper($report->getSeverity()),
                $report->getTitle()
            );
        }
        $choices['q'] = '<comment>Quit interactive mode</comment>';

        while (true) {
            $selected = $io->choice('Choose a finding', $choices, 'q');

            if ($selected === '<comment>Quit interactive mode</comment>') {
                break;
            }

            // Extract the numeric key
            $key = array_search($selected, $choices, true);
            if ($key === false || !is_numeric($key)) {
                continue;
            }

            $reportIndex = (int) $key - 1;
            if (!isset($validReports[$reportIndex])) {
                continue;
            }

            $report = $validReports[$reportIndex];

            $io->newLine();
            $io->writeln(sprintf(
                '<fg=white;options=bold>▌ %s</>',
                $report->getTitle()
            ));
            $io->writeln(sprintf(
                '   <fg=gray>Severity:</> <fg=%s>%s</>   <fg=gray>Confidence:</> %d%%',
                $this->severityColor($report->getSeverity()),
                strtoupper($report->getSeverity()),
                $report->getConfidence()
            ));
            $io->newLine();

            $io->writeln('<fg=gray>Evidence</>');
            $io->writeln('  ' . wordwrap($report->getEvidence(), 78, "\n  "));
            $io->newLine();

            $io->writeln('<fg=gray>Remediation</>');
            $io->writeln('  ' . wordwrap($report->getRemediation(), 78, "\n  "));
            $io->newLine(2);

            if (!$io->confirm('Explore another finding?', true)) {
                break;
            }
        }

        $io->success('Interactive session ended. Thank you for using Sentinel AI.');
    }

    private function severityEmoji(string $severity): string
    {
        return match (strtolower($severity)) {
            'critical' => '🚨',
            'high' => '🔴',
            'medium' => '🟠',
            'low' => '🔵',
            default => '⚪',
        };
    }

    private function severityColor(string $severity): string
    {
        return match (strtolower($severity)) {
            'critical' => 'rose',
            'high' => 'orange',
            'medium' => 'amber',
            'low' => 'sky',
            default => 'zinc',
        };
    }
}
