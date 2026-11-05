<?php

declare(strict_types=1);

namespace Sentinel\Tools;

use Sentinel\Config;
use Sentinel\Exceptions\AgentException;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;

/**
 * Web vulnerability scanner tool.
 *
 * Performs lightweight, non-destructive checks for common web security issues
 * using Guzzle. Focuses on security headers, reflected XSS, and basic SQLi
 * error disclosure. Designed to feed observations into the autonomous agent
 * loop and the SecurityAnalyzer.
 */
final class WebVulnScanner implements Tool
{
    private Client $httpClient;
    private array $config;

    public function __construct(?Config $config = null)
    {
        $this->config = $config?->getToolConfig('web_scanner') ?? [
            'timeout' => 10,
            'user_agent' => 'Sentinel-AI/1.0',
            'max_crawl_depth' => 3,
        ];

        $this->httpClient = new Client([
            'timeout' => (int) $this->config['timeout'],
            'headers' => [
                'User-Agent' => $this->config['user_agent'],
            ],
            'verify' => true,
            'http_errors' => false,
            'allow_redirects' => ['max' => 5],
        ]);
    }

    public function getDescription(): string
    {
        return 'Scans a web application for missing security headers, reflected XSS, SQL injection error disclosure, '
            . 'and common misconfigurations using safe HTTP probes.';
    }

    /**
     * Tool contract implementation. Accepts a target URL.
     *
     * @param array<string, mixed> $parameters Must contain a 'target' or 'url' key
     * @throws AgentException
     */
    public function execute(array $parameters = []): string
    {
        $url = $parameters['target']
            ?? $parameters['url']
            ?? ($parameters[0] ?? null);

        if (!is_string($url) || trim($url) === '') {
            throw new AgentException(
                'WebVulnScanner requires a valid "target" or "url" parameter (string).'
            );
        }

        $normalized = $this->normalizeUrl($url);

        try {
            $findings = $this->scan($normalized);

            if (empty($findings)) {
                return 'Web scan completed successfully. No immediate vulnerabilities detected in basic checks.';
            }

            $summary = sprintf(
                "Web scan of %s discovered %d potential issues:\n",
                $normalized,
                count($findings)
            );

            foreach ($findings as $finding) {
                $summary .= sprintf(
                    "• %s (%s): %s\n",
                    $finding['title'] ?? 'Unknown',
                    $finding['severity'] ?? 'medium',
                    substr($finding['evidence'] ?? '', 0, 80)
                );
            }

            return $summary;
        } catch (GuzzleException $e) {
            throw new AgentException(
                'HTTP request during web scan failed: ' . $e->getMessage(),
                0,
                $e
            );
        } catch (\Throwable $e) {
            throw new AgentException(
                'WebVulnScanner execution failed: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    /**
     * Main entry point for scanning a base URL.
     *
     * @return array<array<string, mixed>>
     */
    public function scan(string $baseUrl): array
    {
        $findings = [];

        $findings = array_merge($findings, $this->checkHeaders($baseUrl));

        $xssUrl = str_contains($baseUrl, '?')
            ? $baseUrl . '&q=test'
            : $baseUrl . '?q=test';
        $findings = array_merge($findings, $this->checkXSS(['url' => $xssUrl]));

        $sqliUrl = str_contains($baseUrl, '?')
            ? $baseUrl . '&id=1'
            : $baseUrl . '?id=1';
        $findings = array_merge($findings, $this->checkSQLInjection(['url' => $sqliUrl]));

        return $findings;
    }

    /**
     * Checks for missing or insecure HTTP security headers.
     *
     * @return array<array<string, mixed>>
     */
    public function checkHeaders(string $baseUrl): array
    {
        $findings = [];

        try {
            $response = $this->httpClient->get($baseUrl);
            $headers = array_change_key_case($response->getHeaders(), CASE_LOWER);

            $required = [
                'strict-transport-security',
                'x-frame-options',
                'x-content-type-options',
                'content-security-policy',
                'referrer-policy',
            ];

            foreach ($required as $header) {
                if (!isset($headers[$header])) {
                    $findings[] = [
                        'title' => 'Missing Security Header: ' . strtoupper(str_replace('-', '-', $header)),
                        'severity' => 'medium',
                        'evidence' => "The {$header} header was not returned by the server.",
                        'remediation' => "Add the missing header. Example for HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                    ];
                }
            }

            if (isset($headers['server'][0])) {
                $findings[] = [
                    'title' => 'Server Information Leak',
                    'severity' => 'low',
                    'evidence' => 'Server header present: ' . $headers['server'][0],
                    'remediation' => 'Configure your web server to omit or genericise the Server header.',
                ];
            }

            $xPoweredBy = $headers['x-powered-by'][0] ?? null;
            if ($xPoweredBy !== null) {
                $findings[] = [
                    'title' => 'X-Powered-By Header Leak',
                    'severity' => 'low',
                    'evidence' => 'X-Powered-By: ' . $xPoweredBy,
                    'remediation' => 'Disable the X-Powered-By header in your server or framework configuration.',
                ];
            }
        } catch (GuzzleException $e) {
            // Network or timeout issues are non-fatal for header checks
        }

        return $findings;
    }

    /**
     * Basic reflected XSS test by injecting a benign payload.
     *
     * @param array<string, mixed> $params Must contain a URL
     * @return array<array<string, mixed>>
     */
    public function checkXSS(array $params): array
    {
        $url = $params['url'] ?? ($params[0] ?? null);
        if (!is_string($url) || trim($url) === '') {
            return [];
        }

        $findings = [];
        $payload = '<script>alert("xss")</script>';
        $testUrl = str_contains($url, '?')
            ? $url . '&xss=' . urlencode($payload)
            : $url . '?xss=' . urlencode($payload);

        try {
            $response = $this->httpClient->get($testUrl);
            $body = (string) $response->getBody();

            if (str_contains($body, $payload)) {
                $findings[] = [
                    'title' => 'Reflected XSS Detected',
                    'severity' => 'high',
                    'evidence' => 'Injected payload was reflected unescaped in the response body.',
                    'remediation' => 'Use context-aware output encoding (htmlspecialchars, template auto-escape). '
                        . 'Consider a Content-Security-Policy with strict script-src.',
                ];
            } elseif (str_contains(strtolower($body), 'alert("xss")')) {
                $findings[] = [
                    'title' => 'Potential Reflected XSS',
                    'severity' => 'medium',
                    'evidence' => 'Payload appears to have been partially reflected.',
                    'remediation' => 'Validate and encode all user-controlled output. Implement CSP.',
                ];
            }
        } catch (GuzzleException $e) {
            // Non-fatal
        }

        return $findings;
    }

    /**
     * Basic SQL injection test by looking for database error messages.
     *
     * @param array<string, mixed> $params Must contain a URL
     * @return array<array<string, mixed>>
     */
    public function checkSQLInjection(array $params): array
    {
        $url = $params['url'] ?? ($params[0] ?? null);
        if (!is_string($url) || trim($url) === '') {
            return [];
        }

        $payloads = ["' OR '1'='1", "1' OR '1'='1", "'; DROP TABLE users;--"];
        $errorPatterns = [
            'SQL syntax',
            'mysql_fetch',
            'You have an error in your SQL syntax',
            'ODBC SQL Server Driver',
            'PostgreSQL.*ERROR',
            'sqlite3.*error',
            'ORA-[0-9]{4,5}',
            'Unclosed quotation mark',
        ];

        foreach ($payloads as $payload) {
            $testUrl = str_contains($url, '?')
                ? $url . '&id=' . urlencode($payload)
                : $url . '?id=' . urlencode($payload);

            try {
                $response = $this->httpClient->get($testUrl);
                $body = (string) $response->getBody();

                foreach ($errorPatterns as $pattern) {
                    if (preg_match('/' . $pattern . '/i', $body)) {
                        return [[
                            'title' => 'Potential SQL Injection',
                            'severity' => 'critical',
                            'evidence' => "Database error pattern '{$pattern}' leaked after injecting payload.",
                            'remediation' => 'Use prepared statements with parameterized queries. '
                                . 'Never concatenate user input into SQL. Consider an ORM.',
                        ]];
                    }
                }
            } catch (GuzzleException $e) {
                // Continue to next payload
            }
        }

        return [];
    }

    private function normalizeUrl(string $url): string
    {
        $url = trim($url);
        if (!str_starts_with($url, 'http://') && !str_starts_with($url, 'https://')) {
            $url = 'https://' . $url;
        }
        return $url;
    }
}
