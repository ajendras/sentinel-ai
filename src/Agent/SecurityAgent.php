<?php

declare(strict_types=1);

namespace Sentinel\Agent;

use Sentinel\Config;
use Sentinel\LLM\LLMInterface;
use Sentinel\Tools\ToolRegistry;
use Sentinel\Tools\ApkDecompiler;
use Sentinel\Tools\WebVulnScanner;
use Sentinel\Analyzers\AndroidManifestAnalyzer;
use Sentinel\Analyzers\SecurityAnalyzer;
use Sentinel\Reporters\Report;
use Sentinel\Exceptions\AgentException;

/**
 * Security-focused agent that extends the core reasoning loop with
 * pre-loaded security prompts, common security tools, and domain-specific
 * analyzers for Android APKs and web applications.
 */
final class SecurityAgent extends CoreAgent
{
    private Config $config;
    private SecurityAnalyzer $securityAnalyzer;
    private AndroidManifestAnalyzer $manifestAnalyzer;

    public function __construct(
        LLMInterface $llm,
        ToolRegistry $toolRegistry,
        Config $config
    ) {
        parent::__construct($llm, $toolRegistry);
        $this->config = $config;

        $this->securityAnalyzer = new SecurityAnalyzer($llm);
        $this->manifestAnalyzer = new AndroidManifestAnalyzer();

        $this->confidenceThreshold = $config->getSecurityConfig()['confidence_threshold'] ?? 65;
        $this->preloadSecurityTools();
    }

    private function preloadSecurityTools(): void
    {
        // Ensure core security tools are registered (idempotent)
        $registry = $this->toolRegistry;

        if (!$registry->has('apk-decompiler')) {
            $registry->register('apk-decompiler', new ApkDecompiler($this->config));
        }

        if (!$registry->has('web-vuln-scanner')) {
            $registry->register('web-vuln-scanner', new WebVulnScanner($this->config));
        }

        // The SecurityAnalyzer is used internally by the agent rather than
        // being exposed as a tool, but could be wrapped if needed.
    }

    /**
     * Runs a complete autonomous security audit for the provided target.
     *
     * @param string $target APK file path or base URL of web application
     * @param string $type Either "android" or "web"
     * @return Report[] Collection of findings (usually 1+ synthesized reports)
     * @throws AgentException
     */
    public function audit(string $target, string $type = 'android'): array
    {
        if (empty($target)) {
            throw new AgentException('Target cannot be empty. Provide an APK path or web URL.');
        }

        if (!in_array($type, ['android', 'web'], true)) {
            throw new AgentException('Type must be either "android" or "web".');
        }

        $objective = $this->buildSecurityObjective($target, $type);
        $this->plan($objective);

        $primaryReport = $this->executeLoop(
            $this->config->getToolConfig()['max_steps'] ?? 12
        );

        // Supplement with static analysis where appropriate
        if ($type === 'android' && file_exists($target)) {
            $extraFindings = $this->performStaticAndroidAnalysis($target);
            // In a full implementation we would merge findings; for now we return the LLM-driven report.
        }

        return [$primaryReport];
    }

    private function buildSecurityObjective(string $target, string $type): string
    {
        if ($type === 'android') {
            return sprintf(
                'Conduct a comprehensive OWASP Mobile Top 10 security audit of the Android application located at %s. ' .
                'Decompile with Apktool, extract and analyze the manifest for dangerous permissions, ' .
                'exported components and backup flags. Examine Smali code for insecure coding patterns, ' .
                'hard-coded secrets, insecure data storage and network communication. Provide concrete ' .
                'evidence, severity ratings and remediation steps for every discovered issue.',
                $target
            );
        }

        return sprintf(
            'Perform an automated web application security assessment starting at %s. ' .
            'Identify XSS, SQL injection, insecure HTTP headers, open redirects, ' .
            'missing security headers and other common misconfigurations. ' .
            'Provide evidence and remediation guidance for each finding.',
            $target
        );
    }

    /**
     * Performs additional static analysis on Android artifacts that does not require LLM.
     *
     * @return Report[]
     */
    private function performStaticAndroidAnalysis(string $apkPath): array
    {
        $reports = [];

        try {
            $decompiler = $this->toolRegistry->get('apk-decompiler');
            if ($decompiler instanceof ApkDecompiler) {
                $decompiler->decompile($apkPath);
                $manifest = $decompiler->getManifest();

                $manifestFindings = $this->manifestAnalyzer->analyze($manifest);
                $reports = array_merge($reports, $manifestFindings);
            }
        } catch (\Throwable $e) {
            // Static analysis failures are non-fatal for the overall audit
            $reports[] = new Report(
                id: 'static-error-' . substr(md5(uniqid()), 0, 8),
                severity: 'low',
                title: 'Static Analysis Partial Failure',
                evidence: $e->getMessage(),
                remediation: 'Ensure Apktool is installed and the APK is valid.',
                confidence: 90
            );
        }

        return $reports;
    }

    /**
     * Override to inject security-specific evaluation logic.
     */
    public function evaluate(string $observation): string
    {
        $evaluation = parent::evaluate($observation);

        // Post-process with SecurityAnalyzer for additional structured findings
        if (str_contains($observation, 'Smali') || str_contains($observation, 'Manifest')) {
            $structured = $this->securityAnalyzer->analyze(
                ['raw' => $observation],
                'android'
            );
            // In full implementation we would merge structured findings into memory.
        }

        return $evaluation;
    }
}
