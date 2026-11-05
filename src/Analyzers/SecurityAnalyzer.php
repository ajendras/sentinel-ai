<?php

declare(strict_types=1);

namespace Sentinel\Analyzers;

use Sentinel\LLM\LLMInterface;
use Sentinel\Prompts\SecurityPrompts;
use Sentinel\Prompts\Prompt;
use Sentinel\Reporters\Report;
use Sentinel\Exceptions\AgentException;

/**
 * LLM-powered analyzer for decompiled artifacts and HTTP responses.
 *
 * Uses the configured LLM (via LLMInterface) and specialized prompts to
 * identify OWASP issues. Parses the free-form LLM response into structured
 * Report objects using heuristics. Designed to be called from SecurityAgent
 * and CoreAgent evaluation steps.
 */
final class SecurityAnalyzer
{
    private LLMInterface $llm;

    public function __construct(LLMInterface $llm)
    {
        $this->llm = $llm;
    }

    /**
     * Analyzes provided artifacts in a given context and returns findings.
     *
     * @param array<string, mixed> $artifacts Raw data (manifest XML, Smali snippets, HTTP responses, headers)
     * @param string $context Either "android" or "web"
     * @return Report[]
     * @throws AgentException
     */
    public function analyze(array $artifacts, string $context = 'android'): array
    {
        if (empty($artifacts)) {
            throw new AgentException('Artifacts array cannot be empty.');
        }

        if (!in_array($context, ['android', 'web'], true)) {
            throw new AgentException(
                sprintf('Context must be "android" or "web", "%s" given.', $context)
            );
        }

        try {
            $prompt = match ($context) {
                'android' => SecurityPrompts::forApkAnalysis($artifacts),
                'web' => SecurityPrompts::forWebVulnTriage($artifacts),
            };

            $responseText = $this->llm->complete($prompt);

            if (trim($responseText) === '') {
                throw new AgentException('LLM returned empty analysis response.');
            }

            return $this->parseLlmResponse($responseText, $context);
        } catch (AgentException $e) {
            throw $e;
        } catch (\Throwable $e) {
            throw new AgentException(
                'Failed to analyze artifacts with LLM: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * Converts the LLM's textual output into an array of Report objects.
     *
     * Uses pattern matching to detect titles, severities, evidence and remediation.
     * Falls back to a single generic report if parsing yields no structured findings.
     *
     * @return Report[]
     */
    private function parseLlmResponse(string $response, string $context): array
    {
        $reports = [];
        $lines = preg_split('/\r?\n/', $response);
        $current = null;
        $section = '';

        foreach ($lines as $rawLine) {
            $line = trim($rawLine);
            if ($line === '') {
                continue;
            }

            // New finding detection
            if (preg_match('/^(?:#{1,3}|\d+\.|\*\*|\-|\•|Finding|Issue|Title)[:\s\-]+/i', $line)) {
                if ($current !== null && isset($current['title']) && trim($current['title']) !== '') {
                    $reports[] = $this->buildReport($current, $context);
                }

                $title = $this->extractTitle($line);
                $current = [
                    'title' => $title,
                    'severity' => 'medium',
                    'evidence' => '',
                    'remediation' => '',
                    'confidence' => 65,
                ];
                $section = 'title';
                continue;
            }

            if ($current === null) {
                continue;
            }

            $lower = strtolower($line);

            if (str_contains($lower, 'severity') || str_contains($lower, 'critical') || str_contains($lower, 'high')) {
                $section = 'severity';
                if (preg_match('/(critical|high|medium|low)/i', $line, $m)) {
                    $current['severity'] = strtolower($m[1]);
                }
                continue;
            }

            if (str_contains($lower, 'evidence') || str_contains($lower, 'found:')) {
                $section = 'evidence';
                continue;
            }

            if (str_contains($lower, 'remediation') || str_contains($lower, 'fix') || str_contains($lower, 'recommend')) {
                $section = 'remediation';
                continue;
            }

            if (str_contains($lower, 'confidence') && preg_match('/(\d{1,3})/', $line, $m)) {
                $current['confidence'] = min(100, max(0, (int) $m[1]));
                continue;
            }

            // Accumulate content
            if ($section === 'evidence') {
                $current['evidence'] .= ($current['evidence'] !== '' ? ' ' : '') . $line;
            } elseif ($section === 'remediation') {
                $current['remediation'] .= ($current['remediation'] !== '' ? ' ' : '') . $line;
            } elseif ($section === 'title' && strlen($current['title']) < 120) {
                $current['title'] .= ' ' . $line;
            }
        }

        // Last finding
        if ($current !== null && isset($current['title']) && trim($current['title']) !== '') {
            $reports[] = $this->buildReport($current, $context);
        }

        if (empty($reports)) {
            // Fallback when parsing completely failed
            $reports[] = new Report(
                id: 'llm-' . $context . '-' . substr(hash('xxh3', $response), 0, 12),
                severity: 'medium',
                title: $context === 'android'
                    ? 'LLM Analysis of Decompiled APK'
                    : 'LLM Analysis of Web Scan Results',
                evidence: substr(trim($response), 0, 420) . (strlen($response) > 420 ? '...' : ''),
                remediation: 'Review the full LLM output for detailed remediation steps. '
                    . 'Consider adding structured JSON output mode in a future LLM client update.',
                confidence: 50
            );
        }

        return $reports;
    }

    private function extractTitle(string $line): string
    {
        return trim((string) preg_replace(
            '/^(?:#{1,3}|\d+\.|\*\*|\-|\•|Finding|Issue|Title)[:\s\-]+/i',
            '',
            $line
        ));
    }

    /**
     * Creates a typed Report from parsed data with safe defaults.
     */
    private function buildReport(array $data, string $context): Report
    {
        $prefix = $context === 'android' ? 'android-' : 'web-';

        return new Report(
            id: $prefix . substr(md5($data['title'] ?? 'finding'), 0, 12),
            severity: $data['severity'] ?? 'medium',
            title: $data['title'] ?? 'Unspecified Security Issue',
            evidence: $data['evidence'] !== ''
                ? $data['evidence']
                : 'Evidence was extracted by the LLM from provided artifacts.',
            remediation: $data['remediation'] !== ''
                ? $data['remediation']
                : 'Follow OWASP Mobile Top 10 / Web Top 10 guidance and re-test after remediation.',
            confidence: $data['confidence'] ?? 65
        );
    }
}
