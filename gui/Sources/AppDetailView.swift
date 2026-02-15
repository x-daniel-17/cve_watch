import SwiftUI

struct AppDetailView: View {
    let app: VulnerableAppModel

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 20) {
                appHeader
                cveList
            }
            .padding(20)
        }
    }

    @ViewBuilder
    private var appHeader: some View {
        HStack(spacing: 16) {
            SeverityBadge(severity: app.maxSeverity, size: .large)

            VStack(alignment: .leading, spacing: 4) {
                Text(app.name)
                    .font(.title2.bold())
                HStack(spacing: 8) {
                    Label("v\(app.version)", systemImage: "tag")
                    Label(app.source, systemImage: "shippingbox")
                }
                .font(.subheadline)
                .foregroundStyle(.secondary)
            }

            Spacer()

            VStack(alignment: .trailing, spacing: 4) {
                if let score = app.maxScore {
                    Text(String(format: "%.1f", score))
                        .font(.system(size: 32, weight: .bold, design: .rounded))
                        .foregroundStyle(app.maxSeverity.color)
                }
                Text("\(app.cves.count) vulnerabilities")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .glassEffect(.regular, in: .rect(cornerRadius: 16))
    }

    @ViewBuilder
    private var cveList: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Vulnerabilities")
                .font(.headline)
                .padding(.horizontal, 4)

            GlassEffectContainer {
                VStack(spacing: 6) {
                    ForEach(sortedCVEs) { cve in
                        CVEDetailRow(cve: cve)
                    }
                }
            }
        }
    }

    private var sortedCVEs: [CVEModel] {
        app.cves.sorted { $0.severity.sortOrder > $1.severity.sortOrder }
    }
}

struct CVEDetailRow: View {
    let cve: CVEModel
    @State private var isExpanded = false

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            // Header row
            Button {
                withAnimation(.spring(duration: 0.3)) {
                    isExpanded.toggle()
                }
            } label: {
                HStack(spacing: 10) {
                    SeverityDot(severity: cve.severity)

                    Text(cve.cveID)
                        .font(.system(.body, design: .monospaced, weight: .medium))
                        .foregroundStyle(.primary)

                    Spacer()

                    if let score = cve.score {
                        Text(String(format: "%.1f", score))
                            .font(.system(.subheadline, design: .rounded, weight: .bold))
                            .foregroundStyle(cve.severity.color)
                            .padding(.horizontal, 8)
                            .padding(.vertical, 3)
                            .background(cve.severity.color.opacity(0.15), in: .capsule)
                    }

                    Text(cve.severity.rawValue)
                        .font(.caption.weight(.semibold))
                        .foregroundStyle(cve.severity.color)

                    Image(systemName: "chevron.right")
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                        .rotationEffect(.degrees(isExpanded ? 90 : 0))
                }
            }
            .buttonStyle(.plain)
            .padding(12)

            // Expanded content
            if isExpanded {
                VStack(alignment: .leading, spacing: 8) {
                    if !cve.description.isEmpty {
                        Text(cve.description)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .textSelection(.enabled)
                    }

                    if let published = cve.published {
                        Label(
                            "Published: \(published.formatted(date: .abbreviated, time: .omitted))",
                            systemImage: "calendar"
                        )
                        .font(.caption)
                        .foregroundStyle(.tertiary)
                    }

                    if !cve.references.isEmpty {
                        HStack(spacing: 4) {
                            Image(systemName: "link")
                                .font(.caption)
                                .foregroundStyle(.tertiary)
                            ForEach(cve.references.prefix(3), id: \.self) { url in
                                Link(destination: URL(string: url)!) {
                                    Text("Reference")
                                        .font(.caption)
                                }
                            }
                        }
                    }
                }
                .padding(.horizontal, 12)
                .padding(.bottom, 12)
                .transition(.opacity.combined(with: .move(edge: .top)))
            }
        }
        .glassEffect(.regular, in: .rect(cornerRadius: 10))
    }
}

struct SeverityDot: View {
    let severity: SeverityLevel

    var body: some View {
        Circle()
            .fill(severity.color.gradient)
            .frame(width: 8, height: 8)
    }
}
