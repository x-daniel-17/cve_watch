import SwiftUI

struct DashboardView: View {
    @Environment(ScannerBridge.self) private var scanner

    var body: some View {
        ScrollView {
            VStack(spacing: 24) {
                headerSection
                if scanner.isScanning {
                    scanProgressSection
                }
                if !scanner.vulnerableApps.isEmpty {
                    criticalSection
                }
                if scanner.allApps.isEmpty && !scanner.isScanning {
                    emptyStateSection
                }
            }
            .padding(24)
        }
        .background(Color(nsColor: .windowBackgroundColor).opacity(0.3))
    }

    @ViewBuilder
    private var headerSection: some View {
        VStack(spacing: 8) {
            Image(systemName: statusIcon)
                .font(.system(size: 48))
                .foregroundStyle(statusGradient)
                .symbolEffect(.pulse, isActive: scanner.isScanning)

            Text(statusTitle)
                .font(.title.bold())

            Text(statusSubtitle)
                .font(.subheadline)
                .foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity)
        .padding(.vertical, 20)
        .glassEffect(.regular, in: .rect(cornerRadius: 20))
    }

    private var statusIcon: String {
        if scanner.isScanning { return "arrow.trianglehead.2.clockwise" }
        if scanner.allApps.isEmpty { return "shield.lefthalf.filled" }
        if scanner.criticalCount > 0 { return "exclamationmark.shield.fill" }
        if scanner.vulnerableApps.isEmpty { return "checkmark.shield.fill" }
        return "shield.lefthalf.filled"
    }

    private var statusTitle: String {
        if scanner.isScanning { return "Scanning…" }
        if scanner.allApps.isEmpty { return "Ready to Scan" }
        if scanner.criticalCount > 0 { return "Critical Vulnerabilities Found" }
        if scanner.vulnerableApps.isEmpty { return "All Clear" }
        return "Vulnerabilities Detected"
    }

    private var statusSubtitle: String {
        if scanner.isScanning { return "Checking installed applications for known CVEs" }
        if scanner.allApps.isEmpty { return "Run a scan to check your installed applications" }
        let total = scanner.totalCVECount
        let apps = scanner.vulnerableApps.count
        let timeStr = scanner.lastScanTime.map {
            " · Last scan \($0.formatted(date: .omitted, time: .shortened))"
        } ?? ""
        if total == 0 { return "No known vulnerabilities in \(scanner.allApps.count) scanned apps\(timeStr)" }
        return "\(total) CVEs found across \(apps) applications\(timeStr)"
    }

    private var statusGradient: some ShapeStyle {
        if scanner.allApps.isEmpty {
            return AnyShapeStyle(Color.secondary.gradient)
        }
        if scanner.criticalCount > 0 {
            return AnyShapeStyle(SeverityLevel.critical.color.gradient)
        }
        if scanner.vulnerableApps.isEmpty {
            return AnyShapeStyle(SeverityLevel.low.color.gradient)
        }
        return AnyShapeStyle(SeverityLevel.high.color.gradient)
    }

    @ViewBuilder
    private var scanProgressSection: some View {
        VStack(spacing: 12) {
            HStack(spacing: 10) {
                ProgressView()
                    .controlSize(.small)

                if scanner.scanTotal > 0 {
                    Text("Checking \(scanner.currentAppName)…")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                } else {
                    Text("Discovering installed applications…")
                        .font(.subheadline)
                        .foregroundStyle(.secondary)
                }

                Spacer()

                if scanner.scanTotal > 0 {
                    Text("\(scanner.scanCurrent) of \(scanner.scanTotal)")
                        .font(.subheadline.monospacedDigit())
                        .foregroundStyle(.tertiary)
                }
            }

            if scanner.scanTotal > 0 {
                ProgressView(value: Double(scanner.scanCurrent), total: Double(scanner.scanTotal))
                    .tint(Color(red: 0.35, green: 0.50, blue: 0.72))
            } else {
                ProgressView()
                    .progressViewStyle(.linear)
            }
        }
        .padding(16)
        .glassEffect(.regular, in: .rect(cornerRadius: 16))
        .transition(.move(edge: .top).combined(with: .opacity))
    }

    @ViewBuilder
    private var criticalSection: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Top Vulnerabilities", systemImage: "exclamationmark.triangle.fill")
                .font(.headline)
                .foregroundStyle(SeverityLevel.critical.color)
                .padding(.horizontal, 4)

            GlassEffectContainer {
                VStack(spacing: 8) {
                    ForEach(topVulnerabilities.prefix(5)) { vuln in
                        CriticalCVERow(app: vuln)
                    }
                }
            }
        }
    }

    private var topVulnerabilities: [VulnerableAppModel] {
        scanner.vulnerableApps.sorted { a, b in
            a.maxSeverity.sortOrder > b.maxSeverity.sortOrder
        }
    }

    @ViewBuilder
    private var emptyStateSection: some View {
        VStack(spacing: 16) {
            Image(systemName: "magnifyingglass")
                .font(.system(size: 40))
                .foregroundStyle(.secondary)

            Text("No scan results yet")
                .font(.title3)
                .foregroundStyle(.secondary)

            Button {
                Task {
                    await scanner.runScan()
                }
            } label: {
                Label("Run First Scan", systemImage: "play.fill")
                    .font(.body.weight(.medium))
                    .padding(.horizontal, 20)
                    .padding(.vertical, 10)
            }
            .buttonStyle(.plain)
            .glassEffect(.regular.interactive())
        }
        .frame(maxWidth: .infinity)
        .padding(40)
    }
}

struct CriticalCVERow: View {
    let app: VulnerableAppModel

    var body: some View {
        HStack(spacing: 12) {
            SeverityBadge(severity: app.maxSeverity)

            VStack(alignment: .leading, spacing: 2) {
                Text(app.name)
                    .font(.body.weight(.medium))
                Text("v\(app.version) • \(app.cves.count) CVEs")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            if let score = app.maxScore {
                Text(String(format: "%.1f", score))
                    .font(.system(.body, design: .rounded, weight: .bold))
                    .foregroundStyle(app.maxSeverity.color)
            }
        }
        .padding(12)
        .glassEffect(.regular, in: .rect(cornerRadius: 12))
    }
}
