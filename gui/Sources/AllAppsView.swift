import SwiftUI

struct AllAppsView: View {
    @Environment(ScannerBridge.self) private var scanner
    @State private var searchText = ""
    @State private var sortOrder = SortOrder.name

    enum SortOrder: String, CaseIterable {
        case name = "Name"
        case source = "Source"
        case version = "Version"
    }

    private var filteredApps: [AppModel] {
        var apps = scanner.allApps
        if !searchText.isEmpty {
            apps = apps.filter {
                $0.name.localizedCaseInsensitiveContains(searchText) ||
                $0.source.localizedCaseInsensitiveContains(searchText)
            }
        }
        switch sortOrder {
        case .name: return apps.sorted { $0.name.lowercased() < $1.name.lowercased() }
        case .source: return apps.sorted { $0.source < $1.source }
        case .version: return apps.sorted { $0.version < $1.version }
        }
    }

    var body: some View {
        VStack(spacing: 0) {
            headerBar
            if filteredApps.isEmpty {
                emptyState
            } else {
                appList
            }
        }
        .searchable(text: $searchText, prompt: "Search applications...")
    }

    @ViewBuilder
    private var headerBar: some View {
        HStack {
            Text("\(scanner.allApps.count) applications discovered")
                .font(.subheadline)
                .foregroundStyle(.secondary)
            Spacer()
            Picker("Sort by", selection: $sortOrder) {
                ForEach(SortOrder.allCases, id: \.self) { order in
                    Text(order.rawValue).tag(order)
                }
            }
            .pickerStyle(.segmented)
            .frame(width: 240)
        }
        .padding(.horizontal, 16)
        .padding(.vertical, 10)
    }

    @ViewBuilder
    private var appList: some View {
        ScrollView {
            LazyVStack(spacing: 4) {
                ForEach(filteredApps) { app in
                    AppRow(app: app, isVulnerable: scanner.isVulnerable(app.name))
                }
            }
            .padding(12)
        }
    }

    @ViewBuilder
    private var emptyState: some View {
        VStack(spacing: 12) {
            Spacer()
            Image(systemName: "questionmark.app")
                .font(.system(size: 36))
                .foregroundStyle(.tertiary)
            Text("No applications found")
                .font(.headline)
                .foregroundStyle(.secondary)
            Spacer()
        }
        .frame(maxWidth: .infinity)
    }
}

struct AppRow: View {
    let app: AppModel
    let isVulnerable: Bool

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: isVulnerable ? "exclamationmark.triangle.fill" : "app.fill")
                .font(.title3)
                .foregroundStyle(isVulnerable ? SeverityLevel.critical.color : .secondary)
                .frame(width: 28)

            VStack(alignment: .leading, spacing: 1) {
                Text(app.name)
                    .font(.body.weight(.medium))
                    .lineLimit(1)
                Text("v\(app.version)")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }

            Spacer()

            SourceBadge(source: app.source)
        }
        .padding(.horizontal, 12)
        .padding(.vertical, 8)
        .glassEffect(.regular, in: .rect(cornerRadius: 8))
    }
}

struct SourceBadge: View {
    let source: String

    var body: some View {
        Text(source)
            .font(.caption2.weight(.medium))
            .padding(.horizontal, 8)
            .padding(.vertical, 3)
            .background(sourceColor.opacity(0.15), in: .capsule)
            .foregroundStyle(sourceColor)
    }

    private var sourceColor: Color {
        switch source {
        case "homebrew": return Color(red: 0.70, green: 0.50, blue: 0.25)
        case "homebrew-cask": return Color(red: 0.55, green: 0.40, blue: 0.65)
        case "applications": return Color(red: 0.35, green: 0.50, blue: 0.72)
        default: return .secondary
        }
    }
}
