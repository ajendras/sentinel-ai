<?php

declare(strict_types=1);

namespace Sentinel\LLM;

use Sentinel\Prompts\Prompt;
use Sentinel\Exceptions\AgentException;

/**
 * Contract for all Large Language Model clients in the Sentinel system.
 *
 * Implementations wrap external LLM providers (OpenAI, Azure, local
 * OpenAI-compatible endpoints) and are used by agents to drive
 * planning, tool selection, evaluation, and report synthesis.
 */
interface LLMInterface
{
    /**
     * Sends the prompt to the LLM and returns the full completion.
     *
     * @param Prompt $prompt The structured prompt (system + user content)
     * @return string The LLM's response text
     * @throws AgentException When the request fails or returns empty
     */
    public function complete(Prompt $prompt): string;

    /**
     * Streams the LLM response token by token, invoking the callback
     * for each chunk. Useful for interactive mode and long-running audits.
     *
     * @param Prompt $prompt The structured prompt
     * @param callable(string $chunk): void $callback Receives each new token
     * @throws AgentException When streaming fails
     */
    public function stream(Prompt $prompt, callable $callback): void;
}
