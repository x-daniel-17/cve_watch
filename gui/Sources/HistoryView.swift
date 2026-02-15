import SwiftUI

struct HistoryView: View {
    @Environment(ScannerBridge.self) private var scanner

    var body: some View {
        VStack(spacing: 0) {
            if scanner.scanHistory.isEmpty {
                emptyState
            } else {
                ScrollView {
                    LazyVStack(spacing: 8) {
                        ForEach(scanner.scanHistory) { entry in
                            HistoryRow(entry: entry)
                        }
                    }
                    .padding(16)
                }
            }
        }
    }

    @ViewBuilder
    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "clock.arrow.circlepath")
                .font(.system(size: 40))
                .foregroundStyle(.tertiary)
            Text("No scan history")
                .font(.headline)
                .foregroundStyle(.secondary)
            Text("Run a scan to start building history")
                .font(.subheadline)
                .foregroundStyle(.tertiary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}

struct HistoryRow: View {
    let entry: ScanHistoryEntry

    var body: some View {
        HStack(spacing: 14) {
            Image(systemName: entry.criticalCount > 0 ? "exclamationmark.shield.fill" : "checkmark.shield.fill")
                .font(.title3)
                .foregroundStyle(entry.criticalCount > 0 ? SeverityLevel.critical.color : SeverityLevel.low.color)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 3) {
                Text(entry.timestamp.formatted(date: .abbreviated, time: .shortened))
                    .font(.body.weight(.medium))
                Text("\(entry.appsScanned) apps scanned")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            HStack(spacing: 16) {
                VStack(alignment: .trailing) {
                    Text("\(entry.totalCVEs)")
                        .font(.system(.body, design: .rounded, weight: .bold))
                    Text("CVEs")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }

                if entry.criticalCount > 0 {
                    VStack(alignment: .trailing) {
                        Text("\(entry.criticalCount)")
                            .font(.system(.body, design: .rounded, weight: .bold))
                            .foregroundStyle(SeverityLevel.critical.color)
                        Text("Critical")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .padding(12)
        .glassEffect(.regular, in: .rect(cornerRadius: 12))
    }
}
