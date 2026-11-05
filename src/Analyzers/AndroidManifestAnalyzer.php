<?php

declare(strict_types=1);

namespace Sentinel\Analyzers;

use Sentinel\Reporters\Report;
use Sentinel\Exceptions\AgentException;
use SimpleXMLElement;

/**
 * Static analyzer for AndroidManifest.xml.
 *
 * Detects dangerous permissions, exported components without protection,
 * debuggable flag, backup flag, and other common manifest misconfigurations.
 * Returns immutable Report value objects.
 */
final class AndroidManifestAnalyzer
{
    /**
     * Analyzes the parsed manifest and returns security findings.
     *
     * @param SimpleXMLElement $manifest The parsed AndroidManifest.xml
     * @return Report[] Ordered list of findings (highest severity first)
     * @throws AgentException
     */
    public function analyze(SimpleXMLElement $manifest): array
    {
        if (!$manifest instanceof SimpleXMLElement) {
            throw new AgentException('Manifest must be a valid SimpleXMLElement.');
        }

        $this->registerAndroidNamespace($manifest);

        $reports = [];

        $application = $manifest->application ?? null;
        if ($application === null) {
            $reports[] = new Report(
                id: 'manifest-error-' . substr(md5(uniqid()), 0, 8),
                severity: 'low',
                title: 'Malformed Manifest',
                evidence: 'No <application> element found.',
                remediation: 'Ensure the APK is valid and contains a complete AndroidManifest.xml.',
                confidence: 90
            );
            return $reports;
        }

        $this->analyzeApplicationFlags($application, $reports);
        $this->analyzeExportedComponents($manifest, $reports);
        $this->analyzePermissions($manifest, $reports);

        // Sort by severity (critical > high > medium > low)
        $severityOrder = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3];
        usort($reports, static fn(Report $a, Report $b): int =>
            ($severityOrder[$a->getSeverity()] ?? 4) <=> ($severityOrder[$b->getSeverity()] ?? 4)
        );

        return $reports;
    }

    private function registerAndroidNamespace(SimpleXMLElement $element): void
    {
        $element->registerXPathNamespace('android', 'http://schemas.android.com/apk/res/android');
    }

    private function analyzeApplicationFlags(SimpleXMLElement $application, array &$reports): void
    {
        $attrs = $application->attributes('http://schemas.android.com/apk/res/android');

        $debuggable = (string) ($attrs['debuggable'] ?? 'false');
        if ($debuggable === 'true') {
            $reports[] = new Report(
                id: 'manifest-debuggable',
                severity: 'high',
                title: 'Debuggable Application',
                evidence: 'android:debuggable="true" is set on the <application> tag.',
                remediation: 'Remove the debuggable attribute (or set it to false) before releasing the application. '
                    . 'Debuggable apps allow arbitrary code execution via ADB.',
                confidence: 95
            );
        }

        $allowBackup = (string) ($attrs['allowBackup'] ?? 'true');
        if ($allowBackup !== 'false') {
            $reports[] = new Report(
                id: 'manifest-allow-backup',
                severity: 'medium',
                title: 'Backup Enabled',
                evidence: 'android:allowBackup is not set to "false" (defaults to true).',
                remediation: 'Add android:allowBackup="false" to the <application> element to prevent '
                    . 'backup of sensitive data via ADB backup.',
                confidence: 85
            );
        }

        $usesCleartextTraffic = (string) ($attrs['usesCleartextTraffic'] ?? 'false');
        if ($usesCleartextTraffic === 'true') {
            $reports[] = new Report(
                id: 'manifest-cleartext-traffic',
                severity: 'high',
                title: 'Cleartext Traffic Permitted',
                evidence: 'android:usesCleartextTraffic="true"',
                remediation: 'Set usesCleartextTraffic="false" and enforce HTTPS. Use Network Security Config '
                    . 'for granular control if cleartext is required for specific domains.',
                confidence: 80
            );
        }
    }

    private function analyzeExportedComponents(SimpleXMLElement $manifest, array &$reports): void
    {
        // Activities
        foreach ($manifest->xpath('//android:activity') ?: [] as $component) {
            $this->checkExportedComponent($component, 'Activity', $reports);
        }

        // Services
        foreach ($manifest->xpath('//android:service') ?: [] as $component) {
            $this->checkExportedComponent($component, 'Service', $reports);
        }

        // Broadcast Receivers
        foreach ($manifest->xpath('//android:receiver') ?: [] as $component) {
            $this->checkExportedComponent($component, 'BroadcastReceiver', $reports);
        }

        // Content Providers
        foreach ($manifest->xpath('//android:provider') ?: [] as $component) {
            $this->checkExportedComponent($component, 'ContentProvider', $reports, true);
        }
    }

    private function checkExportedComponent(
        SimpleXMLElement $component,
        string $type,
        array &$reports,
        bool $isProvider = false
    ): void {
        $attrs = $component->attributes('http://schemas.android.com/apk/res/android');
        $name = (string) ($attrs['name'] ?? 'unknown.' . uniqid());
        $exported = (string) ($attrs['exported'] ?? '');

        // On Android 12+ exported must be explicitly declared for components with intent-filters
        $hasIntentFilter = count($component->xpath('./intent-filter')) > 0;

        if ($exported === 'true' || ($hasIntentFilter && $exported === '')) {
            $permission = (string) ($attrs['permission'] ?? '');
            if ($permission === '') {
                $severity = $isProvider ? 'high' : 'medium';
                $reports[] = new Report(
                    id: 'exported-' . strtolower($type) . '-' . substr(md5($name), 0, 8),
                    severity: $severity,
                    title: "Exported {$type} Without Protection",
                    evidence: "{$type} {$name} is exported but has no android:permission attribute.",
                    remediation: "Set android:exported=\"false\" if the component does not need to be called by "
                        . "other applications. Otherwise protect it with a custom permission declared with "
                        . "android:protectionLevel=\"signature\".",
                    confidence: $isProvider ? 90 : 75
                );
            }
        }
    }

    private function analyzePermissions(SimpleXMLElement $manifest, array &$reports): void
    {
        $dangerousPermissions = [
            'android.permission.READ_EXTERNAL_STORAGE',
            'android.permission.WRITE_EXTERNAL_STORAGE',
            'android.permission.MANAGE_EXTERNAL_STORAGE',
            'android.permission.CAMERA',
            'android.permission.RECORD_AUDIO',
            'android.permission.ACCESS_FINE_LOCATION',
            'android.permission.ACCESS_COARSE_LOCATION',
            'android.permission.READ_PHONE_STATE',
            'android.permission.READ_SMS',
            'android.permission.SEND_SMS',
            'android.permission.READ_CONTACTS',
            'android.permission.WRITE_CONTACTS',
        ];

        $declared = [];
        foreach ($manifest->xpath('//android:uses-permission') ?: [] as $perm) {
            $name = (string) ($perm->attributes('http://schemas.android.com/apk/res/android')['name'] ?? '');
            if ($name !== '') {
                $declared[] = $name;
            }
        }

        $foundDangerous = array_intersect($dangerousPermissions, $declared);

        if (count($foundDangerous) > 0) {
            $reports[] = new Report(
                id: 'dangerous-permissions',
                severity: 'medium',
                title: 'Dangerous Permissions Declared',
                evidence: 'Application declares: ' . implode(', ', $foundDangerous),
                remediation: 'Follow the principle of least privilege. Request only permissions that are '
                    . 'strictly necessary. Use runtime permission requests (Android 6.0+) and provide '
                    . 'clear justification to the user. Consider using App Set ID or other privacy-friendly '
                    . 'alternatives where possible.',
                confidence: 80
            );
        }

        if (in_array('android.permission.INTERNET', $declared, true)) {
            // Common but worth noting when combined with other risks
            $reports[] = new Report(
                id: 'internet-permission',
                severity: 'low',
                title: 'Internet Permission',
                evidence: 'android.permission.INTERNET is declared (common for most apps).',
                remediation: 'Ensure all network communication uses HTTPS. Implement certificate pinning '
                    . 'or use OkHttp\'s CertificatePinner for sensitive connections.',
                confidence: 60
            );
        }
    }
}
