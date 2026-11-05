<?php

declare(strict_types=1);

namespace Sentinel\Agent;

use Sentinel\Config;
use Sentinel\Tools\ToolRegistry;
use Sentinel\LLM\LLMInterface;
use Sentinel\Exceptions\AgentException;

/**
 * Creates the correct specialized agent depending on the audit type.
 *
 * Currently all audit types are handled by SecurityAgent (which internally
 * combines LLM reasoning with static analysis). This factory provides
 * a clean extension point for future AnalysisAgent variants.
 */
final class AgentFactory
{
    public function __construct(
        private readonly Config $config,
        private readonly ToolRegistry $toolRegistry,
        private readonly LLMInterface $llm
    ) {
    }

    /**
     * Factory method to obtain an agent for the requested audit type.
     *
     * @param string $type The type of audit: "android", "web", or "analysis"
     * @return CoreAgent The configured agent ready for audit()
     * @throws AgentException for unsupported types
     */
    public function create(string $type = 'android'): CoreAgent
    {
        if (!in_array($type, ['android', 'web', 'analysis'], true)) {
            throw new AgentException(
                sprintf('Unsupported audit type "%s". Must be one of: android, web, analysis.', $type)
            );
        }

        return match ($type) {
            'android', 'web' => $this->createSecurityAgent(),
            'analysis' => $this->createAnalysisAgent(),
        };
    }

    private function createSecurityAgent(): SecurityAgent
    {
        return new SecurityAgent(
            $this->llm,
            $this->toolRegistry,
            $this->config
        );
    }

    private function createAnalysisAgent(): CoreAgent
    {
        // All current audit types are handled by the SecurityAgent which
        // combines autonomous LLM loops with static manifest/Smali analysis.
        // This maintains full compatibility with the AuditCommand.
        return $this->createSecurityAgent();
    }
}
