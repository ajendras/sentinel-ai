<?php

declare(strict_types=1);

namespace Sentinel\Prompts;

use Sentinel\Exceptions\AgentException;

/**
 * Static factory providing specialized Prompt instances for different
 * stages of the autonomous security audit reasoning loop.
 *
 * Each method crafts a precise, role-specific prompt that guides the LLM
 * toward structured, evidence-based security findings. Covers APK analysis,
 * web vuln triage and remediation suggestions.
 */
final class SecurityPrompts
{
    /**
     * Creates a prompt that asks the LLM to break down the high-level
     * objective into concrete, actionable steps.
     *
     * @throws AgentException
     */
    public static function forPlanning(string $objective): Prompt
    {
        if (trim($objective) === '') {
            throw new AgentException('Objective cannot be empty for planning prompt.');
        }

        $content = <<<PROMPT
You are planning an autonomous security audit.

Objective: {$objective}

Create a concise, ordered list of 4-8 steps. Each step should mention:
- What will be analyzed (manifest, permissions, specific Smali patterns, web endpoints...)
- Which tool should be used
- What specific security properties to look for

Output format: Only a numbered list. No extra commentary.
PROMPT;

        return new Prompt($content);
    }

    /**
     * Prompt for dynamic tool selection based on current context and memory.
     *
     * @param array<string, mixed> $context
     */
    public static function forToolSelection(array $context): Prompt
    {
        $contextJson = json_encode($context, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        $content = <<<PROMPT
Given the current audit state, select the SINGLE most appropriate tool.

Context:
{$contextJson}

Respond with ONLY the exact name of the tool from the available tools list. Do not add any other text.
PROMPT;

        return new Prompt($content);
    }

    /**
     * Prompt used in the main reasoning loop to decide next action or to conclude.
     */
    public static function forDecision(string $objective, string $lastObservation, array $memory): Prompt
    {
        $memorySummary = self::summarizeMemory($memory);

        $content = <<<PROMPT
Objective: {$objective}

Recent observation: {$lastObservation}

Audit memory so far:
{$memorySummary}

Decide the next step:
- If you have enough information to produce the final report, respond with "TERMINATE - ready for final report"
- Otherwise respond with the next concrete goal (1 sentence) that advances the security audit.

Be specific about what to look for (e.g. "check for hardcoded API keys in Smali", "test for reflected XSS").
PROMPT;

        return new Prompt($content);
    }

    /**
     * Prompt for evaluating a tool result in context of the security objective.
     */
    public static function forEvaluation(string $objective, string $observation, array $memory): Prompt
    {
        $memorySummary = self::summarizeMemory($memory);

        $content = <<<PROMPT
Objective: {$objective}

New observation:
{$observation}

Previous memory summary:
{$memorySummary}

Analyze this observation for security issues. 
Extract any concrete evidence of vulnerabilities.
Rate severity internally (critical, high, medium, low).
Suggest what should be done next if more analysis is needed.

Provide your evaluation as clear bullet points.
PROMPT;

        return new Prompt($content);
    }

    /**
     * Prompt to synthesize all the memory into a final Report.
     */
    public static function forFinalReport(string $objective, array $memory): Prompt
    {
        $memoryJson = json_encode($memory, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        $content = <<<PROMPT
You have completed an autonomous security audit.

Objective:
{$objective}

Full audit trail:
{$memoryJson}

Synthesize a professional security report. Identify all distinct findings.
For each finding provide:
- Title
- Severity (critical/high/medium/low)
- Evidence (exact snippet or value from the artifacts)
- Remediation (specific, actionable developer advice with code examples where possible)
- Confidence (integer 0-100)

Structure the output as a clear list of findings. Start with the most severe.
PROMPT;

        return new Prompt($content);
    }

    /**
     * Specialized prompt for APK analysis (used by SecurityAnalyzer).
     *
     * @param array<string, mixed> $artifacts
     */
    public static function forApkAnalysis(array $artifacts): Prompt
    {
        $artifactsStr = json_encode($artifacts, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        $content = <<<PROMPT
Analyze the following decompiled Android APK artifacts for OWASP Mobile Top 10 issues.

Artifacts:
{$artifactsStr}

Focus on:
- Dangerous permissions and their actual usage
- Exported components without proper protection
- Insecure data storage in Smali (SharedPreferences, file I/O, SQLite)
- Hardcoded credentials or API keys
- Insecure network communication (http, no certificate pinning)
- Debuggable flag, backup flag, other manifest misconfigs

List each finding with severity, evidence (code line or XML attribute), and remediation.
PROMPT;

        return new Prompt($content);
    }

    /**
     * Prompt for triaging web vulnerability scan results.
     *
     * @param array<string, mixed> $scanResults
     */
    public static function forWebVulnTriage(array $scanResults): Prompt
    {
        $resultsStr = json_encode($scanResults, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        $content = <<<PROMPT
Triage the following web scan results for OWASP Web Top 10 issues.

Scan results:
{$resultsStr}

For each potential issue:
- Confirm if it is a real vulnerability
- Assign severity
- Provide evidence from the response/headers
- Give precise remediation steps

Output only confirmed issues. Ignore false positives.
PROMPT;

        return new Prompt($content);
    }

    /**
     * Prompt for generating remediation advice for a specific finding.
     */
    public static function forRemediation(string $findingTitle, string $evidence): Prompt
    {
        $content = <<<PROMPT
Provide detailed, production-ready remediation steps for the following security finding:

Title: {$findingTitle}
Evidence: {$evidence}

Include:
- Root cause explanation
- Secure code example (Kotlin/Java for Android, PHP/JS for web)
- Additional best practices
- References to official documentation (OWASP, Android developer guides)

Be concise but complete.
PROMPT;

        return new Prompt($content);
    }

    /**
     * Summarizes recent memory entries for inclusion in prompts.
     */
    private static function summarizeMemory(array $memory): string
    {
        $summary = [];
        $recent = array_slice($memory, -8);

        foreach ($recent as $entry) {
            if (!is_array($entry)) {
                continue;
            }
            $type = $entry['type'] ?? 'unknown';
            $line = match ($type) {
                'tool_selection' => "Tool: {$entry['tool'] ?? 'unknown'} Goal: " . substr($entry['goal'] ?? '', 0, 60),
                'evaluation' => 'Eval: ' . substr($entry['content'] ?? '', 0, 70),
                default => ucfirst($type) . ': ' . substr(json_encode($entry, JSON_UNESCAPED_SLASHES), 0, 70),
            };
            $summary[] = '- ' . $line;
        }

        return implode("\n", $summary) ?: '(no prior memory)';
    }
}

/**
 * Immutable value object representing a prompt sent to an LLM.
 *
 * The LLM client prepends its own security-focused system prompt.
 */
final class Prompt
{
    /**
     * @param string $content User message content (the actual prompt)
     * @throws AgentException
     */
    public function __construct(
        private readonly string $content
    ) {
        if (trim($content) === '') {
            throw new AgentException('Prompt content cannot be empty.');
        }
    }

    public function __toString(): string
    {
        return $this->content;
    }

    public function getContent(): string
    {
        return $this->content;
    }
}
