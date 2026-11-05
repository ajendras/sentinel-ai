<?php

declare(strict_types=1);

namespace Sentinel\Exceptions;

use RuntimeException;
use Throwable;

/**
 * Base exception for the Sentinel AI agent framework.
 *
 * Forms the root of a custom exception hierarchy used for configuration
 * validation failures, LLM communication errors, tool execution problems
 * and reasoning loop issues. Specific categories are indicated via error codes.
 */
class AgentException extends RuntimeException
{
    /** Configuration file, validation or environment errors */
    public const CONFIG_ERROR = 100;

    /** LLM request, parsing or model response errors */
    public const LLM_ERROR = 200;

    /** Tool execution, shell command or external binary failures */
    public const TOOL_ERROR = 300;

    /** Planning, tool selection, evaluation or loop termination errors */
    public const REASONING_ERROR = 400;

    /**
     * @param string $message Human-readable description with context
     * @param int $code One of the class constants (CONFIG_ERROR, LLM_ERROR, ...)
     * @param Throwable|null $previous Underlying exception for chaining
     */
    public function __construct(string $message = '', int $code = 0, ?Throwable $previous = null)
    {
        if ($message === '') {
            $message = 'An unexpected error occurred in the Sentinel agent.';
        }

        parent::__construct($message, $code, $previous);
    }
}
