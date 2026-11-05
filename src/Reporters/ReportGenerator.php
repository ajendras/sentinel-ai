<?php

declare(strict_types=1);

namespace Sentinel\Reporters;

use RuntimeException;
use Symfony\Component\Console\Style\SymfonyStyle;

/**
 * Generates multiple output formats from an array of Report objects.
 *
 * Supports rich console output (tables + details), JSON for machine consumption,
 * and a self-contained HTML report using Tailwind CSS with dark/light mode support,
 * responsive cards, subtle hover transitions and accessible contrast.
 */
final class ReportGenerator
{
    /**
     * Renders findings to the console using SymfonyStyle with color coding,
     * severity emojis and formatted details.
     *
     * @param Report[] $reports
     */
    public function generateConsole(array $reports, SymfonyStyle $io): void
    {
        $validReports = array_filter($reports, static fn($r): bool => $r instanceof Report);

        if (empty($validReports)) {
            $io->warning('No security findings were produced by the audit.');
            return;
        }

        $io->title('Security Audit Results');

        $tableRows = [];
        foreach ($validReports as $report) {
            $severity = strtoupper($report->getSeverity());
            $emoji = $this->severityToEmoji($report->getSeverity());
            $tableRows[] = [
                sprintf('<fg=%s>%s %s</>', $this->severityToColor($report->getSeverity()), $emoji, $severity),
                $report->getTitle(),
                sprintf('%d%%', $report->getConfidence()),
            ];
        }

        $io->table(['Severity', 'Finding', 'Confidence'], $tableRows);

        $io->section('Detailed Findings');
        foreach ($validReports as $index => $report) {
            $color = $this->severityToColor($report->getSeverity());
            $io->writeln(sprintf(
                '<fg=%s;options=bold>%d. %s</>',
                $color,
                $index + 1,
                $report->getTitle()
            ));

            $io->writeln(sprintf(
                '   <fg=gray>Evidence:</> %s',
                wordwrap($report->getEvidence(), 75, "\n             ")
            ));

            $io->writeln(sprintf(
                '   <fg=gray>Remediation:</> %s',
                wordwrap($report->getRemediation(), 75, "\n                ")
            ));

            if ($index < count($validReports) - 1) {
                $io->newLine();
            }
        }

        $io->newLine();
    }

    /**
     * Writes a machine-readable JSON report to disk.
     *
     * @param Report[] $reports
     * @throws RuntimeException When the file cannot be written
     */
    public function saveJson(array $reports, string $filePath): void
    {
        $data = array_map(
            static fn(Report $r): array => $r->toArray(),
            array_filter($reports, static fn($r): bool => $r instanceof Report)
        );

        $json = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

        $directory = dirname($filePath);
        if (!is_dir($directory) && !mkdir($directory, 0755, true) && !is_dir($directory)) {
            throw new RuntimeException(sprintf('Could not create directory "%s".', $directory));
        }

        if (file_put_contents($filePath, $json) === false) {
            throw new RuntimeException(sprintf('Failed to write JSON report to "%s".', $filePath));
        }
    }

    /**
     * Writes a beautiful self-contained HTML report (Tailwind + dark mode) to disk.
     *
     * @param Report[] $reports
     * @throws RuntimeException When the file cannot be written
     */
    public function saveHtml(array $reports, string $filePath): void
    {
        $html = $this->buildHtmlReport($reports);

        $directory = dirname($filePath);
        if (!is_dir($directory) && !mkdir($directory, 0755, true) && !is_dir($directory)) {
            throw new RuntimeException(sprintf('Could not create directory "%s".', $directory));
        }

        if (file_put_contents($filePath, $html) === false) {
            throw new RuntimeException(sprintf('Failed to write HTML report to "%s".', $filePath));
        }
    }

    /**
     * Builds a complete, standalone HTML document with Tailwind via CDN.
     */
    private function buildHtmlReport(array $reports): string
    {
        $validReports = array_filter($reports, static fn($r): bool => $r instanceof Report);
        $findingsHtml = '';

        foreach ($validReports as $report) {
            $severity = $report->getSeverity();
            $color = match ($severity) {
                'critical' => 'rose',
                'high' => 'orange',
                'medium' => 'amber',
                'low' => 'blue',
                default => 'zinc',
            };

            $findingsHtml .= <<<HTML
    <div class="finding bg-white dark:bg-zinc-800 border border-{$color}-200 dark:border-{$color}-800 rounded-3xl p-8 shadow-sm hover:shadow-xl transition-all duration-300">
        <div class="flex justify-between items-start mb-6">
            <span class="inline-flex items-center px-4 py-1.5 rounded-2xl text-sm font-semibold bg-{$color}-100 dark:bg-{$color}-900 text-{$color}-700 dark:text-{$color}-300">
                {$severity}
            </span>
            <span class="text-xs font-mono text-zinc-400 dark:text-zinc-500">
                {$report->getConfidence()}% confidence
            </span>
        </div>
        
        <h3 class="text-2xl font-semibold text-zinc-900 dark:text-white mb-5 leading-tight">
            {$this->escapeHtml($report->getTitle())}
        </h3>
        
        <div class="mb-8">
            <div class="flex items-center gap-2 text-xs uppercase tracking-widest text-zinc-500 mb-3">
                <span class="w-2 h-px bg-current"></span>
                EVIDENCE
            </div>
            <div class="bg-zinc-100 dark:bg-zinc-900 p-5 rounded-2xl font-mono text-sm leading-relaxed text-rose-700 dark:text-rose-400 whitespace-pre-wrap">
                {$this->escapeHtml($report->getEvidence())}
            </div>
        </div>
        
        <div>
            <div class="flex items-center gap-2 text-xs uppercase tracking-widest text-zinc-500 mb-3">
                <span class="w-2 h-px bg-current"></span>
                REMEDIATION
            </div>
            <div class="prose dark:prose-invert text-zinc-600 dark:text-zinc-400 text-[15px] leading-relaxed">
                {$this->escapeHtml($report->getRemediation())}
            </div>
        </div>
    </div>
HTML;
        }

        $generatedAt = date('F j, Y \a\t g:ia');
        $count = count($validReports);

        return <<<HTML
<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Sentinel AI • Security Audit Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&amp;family=Space+Grotesk:wght@500;600&amp;display=swap');
        
        :root {
            --primary: 234 179 8;
        }
        
        body {
            font-family: 'Inter', system_ui, sans-serif;
        }
        
        .logo-font {
            font-family: 'Space Grotesk', sans-serif;
        }
        
        .finding {
            transition: all 0.3s cubic-bezier(0.4, 0.0, 0.2, 1);
        }
        
        .finding:hover {
            transform: translateY(-8px);
            box-shadow: 0 25px 50px -12px rgb(0 0 0 / 0.4);
        }
        
        .tail-text {
            font-feature-settings: "ss01";
        }
    </style>
</head>
<body class="bg-zinc-950 text-zinc-200">
    <div class="max-w-4xl mx-auto px-6 py-12">
        <!-- Header -->
        <div class="flex items-center justify-between mb-16">
            <div class="flex items-center gap-x-5">
                <div class="w-12 h-12 bg-yellow-400 text-zinc-950 rounded-3xl flex items-center justify-center text-4xl shadow-inner">
                    🛡️
                </div>
                <div>
                    <h1 class="logo-font text-5xl font-semibold tracking-tighter text-white">sentinel</h1>
                    <p class="text-yellow-400 text-sm tracking-[3px] -mt-1 font-medium">AI POWERED AUDITOR</p>
                </div>
            </div>
            
            <div class="text-right">
                <div class="inline-flex items-center gap-x-2 bg-zinc-900 px-5 py-2.5 rounded-3xl text-sm">
                    <div class="w-2 h-2 bg-emerald-400 rounded-full animate-pulse"></div>
                    <span class="font-mono text-emerald-400">COMPLETE</span>
                </div>
                <div class="mt-3 text-xs text-zinc-500">{$generatedAt}</div>
            </div>
        </div>

        <div class="flex justify-between items-end mb-10">
            <div>
                <span class="px-4 py-2 bg-white/10 text-white text-sm font-medium rounded-3xl">{$count} FINDINGS</span>
                <h2 class="text-4xl font-semibold text-white mt-4 tracking-tight">Security Audit Report</h2>
                <p class="text-zinc-400 mt-2 max-w-md">Autonomous analysis combining Apktool decompilation, static rules and LLM reasoning.</p>
            </div>
            
            <div class="text-right text-xs font-mono text-zinc-500">
                POWERED BY<br>
                <span class="text-yellow-300">LLM + OWASP KNOWLEDGE</span>
            </div>
        </div>

        <div class="space-y-10">
            {$findingsHtml}
        </div>

        <!-- Footer -->
        <div class="mt-20 pt-8 border-t border-zinc-800 flex items-center justify-between text-xs text-zinc-500">
            <div>
                Generated by <span class="font-medium text-white">Sentinel AI</span><br>
                Open source • PHP 8.3 + Symfony
            </div>
            <div class="text-right">
                <a href="https://github.com/sentinel-ai/sentinel-ai" 
                   target="_blank"
                   class="hover:text-yellow-300 transition-colors flex items-center gap-x-1">
                    <i class="fa-brands fa-github"></i>
                    <span>github.com/sentinel-ai</span>
                </a>
            </div>
        </div>
    </div>

    <script>
        function initializeTailwind() {
            tailwind.config = {
                content: [],
                theme: {
                    extend: {
                        fontFamily: {
                            sans: ['Inter', 'system_ui', 'sans-serif'],
                        }
                    }
                },
                darkMode: 'class',
            };
        }
        initializeTailwind();
    </script>
</body>
</html>
HTML;
    }

    private function severityToEmoji(string $severity): string
    {
        return match (strtolower($severity)) {
            'critical' => '🚨',
            'high' => '🔴',
            'medium' => '🟠',
            'low' => '🔵',
            default => '⚪',
        };
    }

    private function severityToColor(string $severity): string
    {
        return match (strtolower($severity)) {
            'critical' => 'rose',
            'high' => 'orange',
            'medium' => 'amber',
            'low' => 'sky',
            default => 'zinc',
        };
    }

    private function escapeHtml(string $text): string
    {
        return htmlspecialchars($text, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
    }
}
