<?php

declare(strict_types=1);

namespace Sentinel\Reporters;

use Sentinel\Exceptions\AgentException;

/**
 * Immutable value object representing a single security finding.
 *
 * Holds all data for a discovered vulnerability or misconfiguration.
 * All properties are readonly after construction. Input is validated
 * with clear error messages. Severity is normalized to lowercase.
 */
final class Report
{
    private readonly string $id;
    private readonly string $severity;
    private readonly string $title;
    private readonly string $evidence;
    private readonly string $remediation;
    private readonly int $confidence;

    /**
     * @param string $id Unique identifier for this finding (e.g. "manifest-debuggable")
     * @param string $severity Must be one of: critical, high, medium, low
     * @param string $title Short, descriptive title of the issue
     * @param string $evidence Concrete evidence from artifacts (XML, code snippet, HTTP response)
     * @param string $remediation Actionable remediation steps with examples where possible
     * @param int $confidence Confidence in the finding (0-100)
     * @throws AgentException When required fields are missing or values are invalid
     */
    public function __construct(
        string $id,
        string $severity,
        string $title,
        string $evidence,
        string $remediation,
        int $confidence = 50
    ) {
        if (trim($id) === '') {
            throw new AgentException('Report ID cannot be empty.');
        }

        if (trim($title) === '') {
            throw new AgentException('Report title cannot be empty.');
        }

        $validSeverities = ['critical', 'high', 'medium', 'low'];
        $normalized = strtolower(trim($severity));
        if (!in_array($normalized, $validSeverities, true)) {
            throw new AgentException(sprintf(
                'Invalid severity "%s". Must be one of: %s.',
                $severity,
                implode(', ', $validSeverities)
            ));
        }

        if (trim($evidence) === '' && trim($remediation) === '') {
            throw new AgentException('At least one of evidence or remediation must be provided.');
        }

        if ($confidence < 0 || $confidence > 100) {
            throw new AgentException('Confidence must be an integer between 0 and 100.');
        }

        $this->id = $id;
        $this->severity = $normalized;
        $this->title = trim($title);
        $this->evidence = trim($evidence);
        $this->remediation = trim($remediation);
        $this->confidence = $confidence;
    }

    public function getId(): string
    {
        return $this->id;
    }

    public function getSeverity(): string
    {
        return $this->severity;
    }

    public function getTitle(): string
    {
        return $this->title;
    }

    public function getEvidence(): string
    {
        return $this->evidence;
    }

    public function getRemediation(): string
    {
        return $this->remediation;
    }

    public function getConfidence(): int
    {
        return $this->confidence;
    }

    /**
     * Returns a serializable array representation of the report.
     *
     * @return array<string, mixed>
     */
    public function toArray(): array
    {
        return [
            'id' => $this->id,
            'severity' => $this->severity,
            'title' => $this->title,
            'evidence' => $this->evidence,
            'remediation' => $this->remediation,
            'confidence' => $this->confidence,
        ];
    }
}
