<?php

declare(strict_types=1);

namespace Sentinel\Tests\Unit;

use PHPUnit\Framework\TestCase;
use Sentinel\Agent\CoreAgent;
use Sentinel\LLM\LLMInterface;
use Sentinel\Tools\ToolRegistry;
use Sentinel\Tools\Tool;
use Sentinel\Prompts\Prompt;
use Sentinel\Prompts\SecurityPrompts;
use Sentinel\Reporters\Report;
use Sentinel\Exceptions\AgentException;
use ReflectionClass;
use ReflectionProperty;

/**
 * Unit tests for the autonomous CoreAgent reasoning loop.
 *
 * Covers planning, dynamic tool selection via LLM, observation evaluation,
 * termination conditions, memory management and error paths. Uses mocks
 * for LLMInterface and ToolRegistry to isolate the agent's decision logic.
 */
final class CoreAgentTest extends TestCase
{
    private LLMInterface $llmMock;
    private ToolRegistry $registryMock;
    private CoreAgent $agent;

    protected function setUp(): void
    {
        $this->llmMock = $this->createMock(LLMInterface::class);
        $this->registryMock = $this->createMock(ToolRegistry::class);
        $this->agent = new CoreAgent($this->llmMock, $this->registryMock);
    }

    private function getPrivateProperty(object $object, string $propertyName): mixed
    {
        $reflection = new ReflectionClass($object);
        $property = $reflection->getProperty($propertyName);
        $property->setAccessible(true);
        return $property->getValue($object);
    }

    public function testPlanThrowsExceptionForEmptyObjective(): void
    {
        $this->expectException(AgentException::class);
        $this->expectExceptionMessage('Objective cannot be empty.');

        $this->agent->plan('');
    }

    public function testPlanGeneratesStructuredStepsAndStoresInMemory(): void
    {
        $objective = 'Perform a security audit of the provided APK';
        $llmResponse = "1. Decompile the APK using apktool\n2. Analyze the manifest for dangerous permissions\n3. Review Smali for insecure patterns\n4. Synthesize findings";

        $this->llmMock->expects($this->once())
            ->method('complete')
            ->with($this->isInstanceOf(Prompt::class))
            ->willReturn($llmResponse);

        $plan = $this->agent->plan($objective);

        $this->assertCount(4, $plan);
        $this->assertStringContainsString('Decompile the APK', $plan[0]);
        $this->assertStringContainsString('Analyze the manifest', $plan[1]);
        $this->assertStringContainsString('Review Smali', $plan[2]);

        $memory = $this->getPrivateProperty($this->agent, 'memory');
        $this->assertCount(1, $memory);
        $this->assertSame('plan', $memory[0]['type']);
        $this->assertSame($plan, $memory[0]['content']);
    }

    public function testPlanHandlesVariousListFormats(): void
    {
        $objective = 'Test parsing';
        $llmResponse = "- Step one\n* Step two\n3. Step three\n\nStep four without prefix";

        $this->llmMock->method('complete')->willReturn($llmResponse);

        $plan = $this->agent->plan($objective);

        $this->assertCount(4, $plan);
        $this->assertSame('Step one', $plan[0]);
        $this->assertSame('Step two', $plan[1]);
        $this->assertSame('Step three', $plan[2]);
        $this->assertSame('Step four without prefix', $plan[3]);
    }

    public function testSelectToolThrowsWhenNoToolsRegistered(): void
    {
        $this->expectException(AgentException::class);
        $this->expectExceptionMessage('No tools registered in the ToolRegistry.');

        $this->registryMock->method('listAll')->willReturn([]);

        // plan() must be called first to set objective
        $this->llmMock->method('complete')->willReturn('plan response');
        $this->agent->plan('test objective');

        $this->agent->selectTool('any goal');
    }

    public function testSelectToolChoosesToolByNameInLlmResponse(): void
    {
        $objective = 'Audit APK';
        $goal = 'Analyze manifest permissions';
        $mockTool = $this->createMock(Tool::class);

        $tools = [
            'apk-decompiler' => $mockTool,
            'web-scanner' => $this->createMock(Tool::class),
        ];

        $this->registryMock->method('listAll')->willReturn($tools);
        $this->registryMock->method('get')
            ->with('apk-decompiler')
            ->willReturn($mockTool);

        $this->llmMock->expects($this->exactly(2)) // once for plan, once for selection
            ->method('complete')
            ->willReturnOnConsecutiveCalls(
                'Some plan',
                'I will use the apk-decompiler tool to extract the manifest.'
            );

        $this->agent->plan($objective);
        $selectedTool = $this->agent->selectTool($goal);

        $this->assertSame($mockTool, $selectedTool);

        $memory = $this->getPrivateProperty($this->agent, 'memory');
        $this->assertTrue(
            array_filter($memory, static fn(array $entry): bool =>
                ($entry['type'] ?? '') === 'tool_selection' && ($entry['tool'] ?? '') === 'apk-decompiler'
            ) !== []
        );
    }

    public function testSelectToolFallsBackToFirstAvailableTool(): void
    {
        $mockTool = $this->createMock(Tool::class);
        $tools = ['fallback-tool' => $mockTool];

        $this->registryMock->method('listAll')->willReturn($tools);
        $this->registryMock->method('get')->willReturn($mockTool);

        $this->llmMock->method('complete')
            ->willReturnOnConsecutiveCalls('plan', 'some response that does not mention any tool name');

        $this->agent->plan('test');
        $selected = $this->agent->selectTool('irrelevant goal');

        $this->assertSame($mockTool, $selected);
    }

    public function testEvaluateUpdatesMemoryWithLlmAssessment(): void
    {
        $observation = 'Found debuggable=true in AndroidManifest.xml';
        $llmEvaluation = 'This is a high severity issue. Evidence: ... Remediation: ...';

        $this->llmMock->expects($this->once())
            ->method('complete')
            ->with($this->isInstanceOf(Prompt::class))
            ->willReturn($llmEvaluation);

        $this->agent->plan('test objective'); // ensure objective is set

        $result = $this->agent->evaluate($observation);

        $this->assertSame($llmEvaluation, $result);

        $memory = $this->getPrivateProperty($this->agent, 'memory');
        $evaluationEntries = array_filter(
            $memory,
            static fn(array $entry): bool => ($entry['type'] ?? '') === 'evaluation'
        );

        $this->assertCount(1, $evaluationEntries);
        $last = array_pop($evaluationEntries);
        $this->assertSame($llmEvaluation, $last['content']);
    }

    public function testEvaluateReturnsFallbackOnLlmFailure(): void
    {
        $this->llmMock->method('complete')
            ->willThrowException(new \RuntimeException('LLM unavailable'));

        $this->agent->plan('test objective');

        $result = $this->agent->evaluate('some observation');

        $this->assertStringStartsWith('Evaluation failed:', $result);
    }

    public function testExecuteLoopTerminatesOnFinalReportDecision(): void
    {
        $this->llmMock->method('complete')
            ->willReturnOnConsecutiveCalls(
                '1. Decompile APK',           // plan
                'Analyze manifest',           // decision 1
                'final report ready',         // decision 2 -> termination
                'Final summary of findings'   // synthesizeFinalReport
            );

        $mockTool = $this->createMock(Tool::class);
        $mockTool->method('execute')->willReturn('tool result');

        $this->registryMock->method('listAll')->willReturn(['apk-decompiler' => $mockTool]);
        $this->registryMock->method('get')->willReturn($mockTool);

        $this->agent->plan('Perform security audit');

        $report = $this->agent->executeLoop(5);

        $this->assertInstanceOf(Report::class, $report);
        $this->assertSame('medium', $report->getSeverity());
        $this->assertStringContainsString('Autonomous Security Audit Findings', $report->getTitle());
    }

    public function testExecuteLoopHandlesToolExecutionErrorGracefully(): void
    {
        $this->llmMock->method('complete')
            ->willReturnOnConsecutiveCalls(
                'plan step',
                'use tool',
                'final report'
            );

        $mockTool = $this->createMock(Tool::class);
        $mockTool->method('execute')
            ->willThrowException(new \RuntimeException('apktool not found'));

        $this->registryMock->method('listAll')->willReturn(['apk-decompiler' => $mockTool]);
        $this->registryMock->method('get')->willReturn($mockTool);

        $this->agent->plan('test');

        $report = $this->agent->executeLoop(3);

        $this->assertInstanceOf(Report::class, $report);
    }

    public function testSynthesizeFinalReportUsesMemoryAndCreatesReport(): void
    {
        $this->llmMock->method('complete')
            ->willReturnOnConsecutiveCalls(
                'initial plan',
                'final summary from memory'
            );

        $this->agent->plan('Test objective');

        // Add some memory entries
        $memoryProp = new ReflectionProperty(CoreAgent::class, 'memory');
        $memoryProp->setAccessible(true);
        $memoryProp->setValue($this->agent, [
            ['type' => 'plan', 'content' => ['step 1']],
            ['type' => 'evaluation', 'content' => 'found issue X'],
        ]);

        $report = $this->agent->executeLoop(2); // will hit termination immediately

        $this->assertInstanceOf(Report::class, $report);
        $this->assertGreaterThan(10, strlen($report->getId()));
        $this->assertSame(65, $report->getConfidence());
    }

    public function testConfidenceThresholdIsConfigurableViaProperty(): void
    {
        $reflection = new ReflectionClass($this->agent);
        $thresholdProp = $reflection->getProperty('confidenceThreshold');
        $thresholdProp->setAccessible(true);

        $thresholdProp->setValue($this->agent, 85);

        $this->llmMock->method('complete')->willReturn('plan');
        $this->agent->plan('test');

        $this->llmMock->method('complete')->willReturn('final report');
        $report = $this->agent->executeLoop(1);

        $this->assertSame(85, $report->getConfidence());
    }
}
