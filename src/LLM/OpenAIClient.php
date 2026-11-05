<?php

declare(strict_types=1);

namespace Sentinel\LLM;

use OpenAI;
use OpenAI\Client as OpenAIClientLib;
use Sentinel\Prompts\Prompt;
use Sentinel\Exceptions\AgentException;

/**
 * OpenAI-compatible LLM client with a security-focused system prompt.
 *
 * Uses the official openai-php/client library. Supports custom base URIs
 * for Azure OpenAI, local models (e.g. Ollama with OpenAI compat layer),
 * or any other OpenAI-compatible endpoint. All responses are forced to
 * low temperature for consistent security reasoning.
 */
final class OpenAIClient implements LLMInterface
{
    private const DEFAULT_TEMPERATURE = 0.0;
    private const DEFAULT_MAX_TOKENS = 2048;

    private OpenAIClientLib $client;
    private string $model;
    private string $systemPrompt;

    /**
     * @param string $apiKey OpenAI (or compatible) API key - never empty
     * @param string $model Model identifier (e.g. gpt-4o-mini, gpt-4-turbo)
     * @param string|null $baseUri Custom endpoint base URI (for Azure, local, etc.)
     */
    public function __construct(
        string $apiKey,
        string $model = 'gpt-4o-mini',
        ?string $baseUri = null
    ) {
        if (trim($apiKey) === '') {
            throw new AgentException(
                'OpenAI API key is required. Provide it in sentinel.json under llm.api_key ' .
                'or set the OPENAI_API_KEY / LLM_API_KEY environment variable.'
            );
        }

        if (trim($model) === '') {
            throw new AgentException('Model name cannot be empty.');
        }

        $this->model = $model;
        $this->systemPrompt = $this->buildSecuritySystemPrompt();

        $factory = OpenAI::factory()->withApiKey($apiKey);

        if ($baseUri !== null && trim($baseUri) !== '') {
            $factory = $factory->withBaseUri($baseUri);
        }

        $this->client = $factory->make();
    }

    public function complete(Prompt $prompt): string
    {
        $userContent = (string) $prompt;
        if (trim($userContent) === '') {
            throw new AgentException('Prompt content cannot be empty.');
        }

        try {
            $response = $this->client->chat()->create([
                'model' => $this->model,
                'messages' => [
                    ['role' => 'system', 'content' => $this->systemPrompt],
                    ['role' => 'user', 'content' => $userContent],
                ],
                'temperature' => self::DEFAULT_TEMPERATURE,
                'max_tokens' => self::DEFAULT_MAX_TOKENS,
            ]);

            $content = $response->choices[0]->message->content ?? '';

            if (trim($content) === '') {
                throw new AgentException('LLM returned empty response.');
            }

            return $content;
        } catch (\Throwable $e) {
            throw new AgentException(
                'LLM completion request failed: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    public function stream(Prompt $prompt, callable $callback): void
    {
        $userContent = (string) $prompt;
        if (trim($userContent) === '') {
            throw new AgentException('Prompt content cannot be empty.');
        }

        try {
            $stream = $this->client->chat()->createStreamed([
                'model' => $this->model,
                'messages' => [
                    ['role' => 'system', 'content' => $this->systemPrompt],
                    ['role' => 'user', 'content' => $userContent],
                ],
                'temperature' => self::DEFAULT_TEMPERATURE,
                'max_tokens' => self::DEFAULT_MAX_TOKENS,
            ]);

            foreach ($stream as $response) {
                $delta = $response->choices[0]->delta->content ?? '';
                if ($delta !== '') {
                    $callback($delta);
                }
            }
        } catch (\Throwable $e) {
            throw new AgentException(
                'LLM streaming request failed: ' . $e->getMessage(),
                0,
                $e
            );
        }
    }

    private function buildSecuritySystemPrompt(): string
    {
        return <<<'PROMPT'
You are Sentinel, a senior autonomous security engineer specializing in Android APK audits and web application security.

Core expertise:
- OWASP Mobile Top 10, OWASP Web Top 10, OWASP API Security
- Android manifest analysis (exported components, dangerous permissions, backup flags, debuggable)
- Smali / DEX code review for insecure coding patterns, hardcoded secrets, insecure data storage, weak crypto, improper certificate validation
- Web vulnerabilities: XSS, SQL injection, insecure headers, open redirects, SSRF, misconfigured CORS, clickjacking
- Evidence-based reasoning only - never hallucinate findings

Response rules (always follow):
1. Base every finding on concrete evidence from the provided artifacts (manifest XML, Smali snippets, HTTP responses, headers).
2. For each issue return: title, severity (critical/high/medium/low), precise evidence (code snippet or exact value), remediation (developer-friendly fix with example), confidence (0-100).
3. Think step-by-step: Observe → Reason → Conclude.
4. Map Smali back to probable Java/Kotlin patterns when helpful.
5. Prioritize high-impact issues first.
PROMPT;
    }
}
