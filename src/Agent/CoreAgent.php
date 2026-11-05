<?php

declare(strict_types=1);

namespace Sentinel\Agent;

use Sentinel\LLM\LLMInterface;
use Sentinel\Tools\ToolRegistry;
use Sentinel\Tools\Tool;
use Sentinel\Prompts\SecurityPrompts;
use Sentinel\Prompts\Prompt;
use Sentinel\Reporters\Report;
use Sentinel\Exceptions\AgentException;

/**
 * Core autonomous agent implementing a ReAct-style reasoning loop.
 *
 * Responsible for high-level planning, dynamic tool selection via LLM,
 * execution of tools through the registry, observation evaluation,
 * and final report synthesis. This is the foundation for all specialized
 * agents in the Sentinel system.
 */
class CoreAgent
{
    protected LLMInterface $llm;
    protected ToolRegistry $toolRegistry;
    protected array $memory = [];
    protected string $objective = '';
    protected int $confidenceThreshold = 65;

    public function __construct(LLMInterface $llm, ToolRegistry $toolRegistry)
    {
        $this->llm = $llm;
        $this->toolRegistry = $toolRegistry;
    }

    /**
     * Creates a structured multi-step plan for the given objective using the LLM.
     *
     * @return array<string> Ordered list of high-level steps
     * @throws AgentException
     */
    public function plan(string $objective): array
    {
        if (empty($objective)) {
            throw new AgentException('Objective cannot be empty.');
        }

        $this->objective = $objective;
        $this->memory = [];

        $prompt = SecurityPrompts::forPlanning($objective);

        try {
            $response = $this->llm->complete($prompt);
            $plan = $this->parseStructuredList($response);

            $this->memory[] = [
                'type' => 'plan',
                'content' => $plan,
                'timestamp' => time(),
            ];

            return $plan;
        } catch (\Throwable $e) {
            throw new AgentException('Failed to generate plan: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Uses the LLM to select the best tool for the current sub-goal.
     *
     * @throws AgentException
     */
    public function selectTool(string $goal): Tool
    {
        if (empty($goal)) {
            throw new AgentException('Tool selection goal cannot be empty.');
        }

        $tools = $this->toolRegistry->listAll();
        if (empty($tools)) {
            throw new AgentException('No tools registered in the ToolRegistry.');
        }

        $toolList = [];
        foreach ($tools as $name => $tool) {
            $toolList[] = sprintf(
                '%s: %s',
                $name,
                method_exists($tool, 'getDescription') ? $tool->getDescription() : 'No description'
            );
        }

        $context = [
            'objective' => $this->objective,
            'current_goal' => $goal,
            'previous_steps' => $this->memory,
            'available_tools' => $toolList,
        ];

        $prompt = SecurityPrompts::forToolSelection($context);

        try {
            $response = trim($this->llm->complete($prompt));
            $selectedName = $this->extractToolName($response, array_keys($tools));

            $tool = $this->toolRegistry->get($selectedName);
            if ($tool === null) {
                throw new AgentException(sprintf('Selected tool "%s" not found in registry.', $selectedName));
            }

            $this->memory[] = [
                'type' => 'tool_selection',
                'tool' => $selectedName,
                'goal' => $goal,
                'timestamp' => time(),
            ];

            return $tool;
        } catch (\Throwable $e) {
            throw new AgentException('Tool selection failed: ' . $e->getMessage(), 0, $e);
        }
    }

    /**
     * Runs the full autonomous reasoning loop until completion or max steps reached.
     *
     * @throws AgentException
     */
    public function executeLoop(int $maxSteps = 10): Report
    {
        if ($this->objective === '') {
            throw new AgentException('Must call plan() before executing the loop.');
        }

        $stepsTaken = 0;
        $lastObservation = 'Audit initialized. No observations yet.';

        while ($stepsTaken < $maxSteps) {
            $stepsTaken++;

            $this->memory[] = [
                'type' => 'step',
                'step_number' => $stepsTaken,
                'observation' => $lastObservation,
            ];

            // Let LLM decide next action or termination
            $decisionPrompt = SecurityPrompts::forDecision($this->objective, $lastObservation, $this->memory);
            $decisionText = $this->llm->complete($decisionPrompt);

            if ($this->isTerminationDecision($decisionText)) {
                break;
            }

            $nextGoal = $this->extractNextGoal($decisionText);
            $tool = $this->selectTool($nextGoal);

            $parameters = $this->extractToolParameters($decisionText);

            try {
                $result = $tool->execute($parameters);
                $lastObservation = $this->evaluate($result);
            } catch (\Throwable $e) {
                $lastObservation = sprintf('Tool execution error: %s', $e->getMessage());
                $this->memory[] = ['type' => 'error', 'content' => $lastObservation];
            }
        }

        return $this->synthesizeFinalReport();
    }

    /**
     * Evaluates a tool observation and updates internal reasoning state.
     */
    public function evaluate(string $observation): string
    {
        $prompt = SecurityPrompts::forEvaluation($this->objective, $observation, $this->memory);

        try {
            $evaluation = $this->llm->complete($prompt);
            $this->memory[] = [
                'type' => 'evaluation',
                'content' => $evaluation,
                'timestamp' => time(),
            ];

            return $evaluation;
        } catch (\Throwable $e) {
            return 'Evaluation failed: ' . $e->getMessage();
        }
    }

    private function parseStructuredList(string $rawResponse): array
    {
        $lines = preg_split('/\r\n|\n|\r/', $rawResponse);
        $steps = [];

        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            // Remove common list prefixes
            $clean = preg_replace('/^[\s\-*\d\.)]+/', '', $line);
            if ($clean !== null && $clean !== '') {
                $steps[] = trim($clean);
            }
        }

        return $steps ?: [$rawResponse];
    }

    private function extractToolName(string $response, array $availableTools): string
    {
        $responseLower = strtolower(trim($response));

        foreach ($availableTools as $toolName) {
            if (str_contains($responseLower, strtolower($toolName))) {
                return $toolName;
            }
        }

        // Default to first available tool as fallback
        return $availableTools[0];
    }

    private function isTerminationDecision(string $decisionText): bool
    {
        $text = strtolower($decisionText);
        return str_contains($text, 'final report')
            || str_contains($text, 'terminate')
            || str_contains($text, 'conclude')
            || str_contains($text, 'finished');
    }

    private function extractNextGoal(string $decisionText): string
    {
        // In production this would parse JSON structured output from the LLM.
        // For robustness we return a generic goal derived from the objective.
        if (str_contains(strtolower($decisionText), 'manifest')) {
            return 'Analyze AndroidManifest.xml for dangerous permissions and exported components';
        }
        if (str_contains(strtolower($decisionText), 'smali') || str_contains(strtolower($decisionText), 'code')) {
            return 'Review Smali code for insecure data storage, insecure communication and other OWASP issues';
        }
        return 'Continue security analysis of decompiled artifacts';
    }

    /**
     * @return array<string, mixed>
     */
    private function extractToolParameters(string $decisionText): array
    {
        // Structured extraction would be implemented with JSON mode in a future LLM update.
        // Current version uses minimal parameters; tools have intelligent defaults.
        return [];
    }

    private function synthesizeFinalReport(): Report
    {
        $prompt = SecurityPrompts::forFinalReport($this->objective, $this->memory);

        try {
            $summary = $this->llm->complete($prompt);

            return new Report(
                id: 'sentinel-' . substr(md5((string) time()), 0, 12),
                severity: 'medium',
                title: 'Autonomous Security Audit Findings',
                evidence: $summary,
                remediation: 'Review each finding below. Prioritize high-severity items. ' .
                            'Apply provided remediation steps and re-run the audit.',
                confidence: $this->confidenceThreshold
            );
        } catch (\Throwable $e) {
            throw new AgentException('Failed to synthesize final report: ' . $e->getMessage(), 0, $e);
        }
    }
}
