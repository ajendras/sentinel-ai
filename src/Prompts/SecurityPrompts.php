<?php

declare(strict_types=1);

namespace Sentinel\Prompts;

/**
 * Centralized prompt templates for all security-related LLM interactions.
 *
 * Each static method returns a well-crafted prompt string that guides the
 * LLM toward structured, actionable security audit output. Prompts are
 * designed to be used by CoreAgent, SecurityAgent and SecurityAnalyzer.
 */
final class SecurityPrompts
{
    /**
     * Prompt used by CoreAgent::plan() to generate a multi-step audit plan.
     */
    public static function forPlanning(string $objective): string
    {
        return <<<PROMPT
You are an expert mobile and web security auditor.
Create a concise, numbered step-by-step plan (4-7 steps) to achieve the following security audit objective:

{$objective}

Output ONLY the numbered list. Do not include any explanations, introductions or closing remarks.
PROMPT;
    }

    /**
     * Prompt used by CoreAgent::selectTool() to pick the next tool.
     *
     * @param array<string, mixed> $context
     */
    public static function forToolSelection(array $context): string
    {
        $objective = $context['objective'] ?? 'Perform a security audit';
        $currentGoal = $context['current_goal'] ?? 'Continue analysis';
        $tools = implode("\n", $context['available_tools'] ?? []);

        return <<<PROMPT
Objective: {$objective}

Current goal: {$currentGoal}

Available tools:
{$tools}

Previous steps: {$context['previous_steps'] ?? 'None'}

Which SINGLE tool should be used next to make progress? Reply with ONLY the exact tool name from the list above.
PROMPT;
    }

    /**
     * Prompt used inside CoreAgent::executeLoop() to decide next action or termination.
     */
    public static function forDecision(string $objective, string $lastObservation, array $memory): string
    {
        $memorySummary = count($memory) > 3
            ? '...' . substr(json_encode(array_slice($memory, -3)), 0, 180)
            : json_encode($memory);

        return <<<PROMPT
You are executing a security audit with this objective:
{$objective}

Last observation:
{$lastObservation}

Recent memory:
{$memorySummary}

Decide the next step. If enough information has been gathered to produce a final report, respond with the phrase "FINAL REPORT". 
Otherwise respond with a short next goal (max 15 words).
Only output the decision text, no extra commentary.
PROMPT;
    }

    /**
     * Prompt used by CoreAgent::evaluate() to interpret tool results.
     */
    public static function forEvaluation(string $objective, string $observation, array $memory): string
    {
        return <<<PROMPT
Objective: {$objective}

New observation from a security tool:
{$observation}

Previous memory summary: {$memory ? substr(json_encode($memory), 0, 250) : 'None'}

Provide a short evaluation (2-4 sentences) of what this observation means for the security posture.
Focus on OWASP risks, severity and any concrete evidence. End with a confidence score (0-100).
PROMPT;
    }

    /**
     * Prompt used by CoreAgent::synthesizeFinalReport() to produce the final output.
     */
    public static function forFinalReport(string $objective, array $memory): string
    {
        $memoryJson = json_encode($memory, JSON_PRETTY_PRINT);

        return <<<PROMPT
You are a senior security engineer writing a final audit report.

Objective:
{$objective}

All observations and evaluations gathered:
{$memoryJson}

Synthesize a concise but actionable security report. For each finding include:
- Title
- Severity (critical, high, medium, low)
- Evidence (exact snippets or URLs)
- Remediation steps

Format the output as clearly separated sections. Use markdown. Only include findings with confidence >= 60.
PROMPT;
    }

    /**
     * Prompt used by SecurityAnalyzer for APK / decompiled code analysis.
     *
     * @param array<string, mixed> $artifacts
     */
    public static function forApkAnalysis(array $artifacts): string
    {
        $artifactSummary = json_encode($artifacts, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        return <<<PROMPT
Analyze the following Android application artifacts for OWASP Mobile Top 10 issues.

Artifacts:
{$artifactSummary}

For every discovered vulnerability return a structured finding containing:
- Title
- Severity (critical/high/medium/low)
- Evidence (code snippets, manifest lines, permission names, etc.)
- Remediation (concrete developer actions)

Only output findings with confidence >= 65. If none are found, reply with "No significant security issues detected."
PROMPT;
    }

    /**
     * Prompt used by SecurityAnalyzer for web vulnerability triage.
     *
     * @param array<string, mixed> $artifacts
     */
    public static function forWebVulnTriage(array $artifacts): string
    {
        $artifactSummary = json_encode($artifacts, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);

        return <<<PROMPT
Triage the following web application scan results for OWASP Web Top 10 issues (XSS, SQLi, insecure headers, etc.).

Scan data:
{$artifactSummary}

For each issue output:
- Title
- Severity
- Evidence (request/response snippets, headers, etc.)
- Remediation

Only report issues with confidence >= 65. Use markdown sections. If nothing is found reply with "No web vulnerabilities detected in this scan."
PROMPT;
    }

    /**
     * Helper used by tests and interactive modes to obtain a generic security prompt.
     */
    public static function genericSecurityPrompt(string $task): string
    {
        return "You are a security expert. " . $task . "\n\nBe concise, evidence-based and provide actionable remediation steps.";
    }
}
