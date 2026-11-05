<?php

declare(strict_types=1);

namespace Sentinel\Tools;

use Sentinel\Exceptions\AgentException;

/**
 * Central registry for all tools available to autonomous agents.
 *
 * Acts as a singleton-like service but can also be instantiated directly
 * (as done in Application.php). Provides easy extension - new tools can be
 * registered in seconds. Includes has() to support the idempotent preload
 * pattern used by SecurityAgent.
 */
final class ToolRegistry
{
    /** @var array<string, Tool> Registered tools */
    private array $tools = [];

    /**
     * Register a new tool under a unique name.
     *
     * Overwrites existing tools with the same name (supports the preload
     * pattern in SecurityAgent).
     *
     * @throws AgentException
     */
    public function register(string $name, Tool $tool): void
    {
        $name = trim($name);
        if ($name === '') {
            throw new AgentException('Tool name cannot be empty.');
        }

        $this->tools[$name] = $tool;
    }

    /**
     * Retrieve a tool by name.
     */
    public function get(string $name): ?Tool
    {
        return $this->tools[trim($name)] ?? null;
    }

    /**
     * Check if a tool with the given name is registered.
     */
    public function has(string $name): bool
    {
        return isset($this->tools[trim($name)]);
    }

    /**
     * Returns all registered tools (name => Tool instance).
     *
     * @return array<string, Tool>
     */
    public function listAll(): array
    {
        return $this->tools;
    }

    /**
     * Returns the number of registered tools.
     */
    public function count(): int
    {
        return count($this->tools);
    }

    /**
     * Static singleton accessor (useful in tests or one-off scripts).
     */
    public static function instance(): self
    {
        static $instance;
        return $instance ??= new self();
    }
}

/**
 * Interface that all executable tools must implement.
 *
 * Tools are selected dynamically by the LLM via the CoreAgent.
 */
interface Tool
{
    /**
     * Executes the tool with optional parameters.
     *
     * @param array<string, mixed> $parameters
     * @return string A human-readable result or summary that becomes an observation for the agent
     * @throws AgentException on failure
     */
    public function execute(array $parameters = []): string;

    /**
     * Short description used by the LLM when selecting tools.
     */
    public function getDescription(): string;
}
