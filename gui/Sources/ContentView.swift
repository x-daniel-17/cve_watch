import SwiftUI

enum SidebarItem: String, Hashable, CaseIterable {
    case dashboard = "Dashboard"
    case vulnerabilities = "Vulnerabilities"
    case allApps = "All Apps"
    case history = "History"

    var icon: String {
        switch self {
        case .dashboard: return "shield.lefthalf.filled"
        case .vulnerabilities: return "exclamationmark.triangle.fill"
        case .allApps: return "app.badge.checkmark"
        case .history: return "clock.arrow.circlepath"
        }
    }
}

struct ContentView: View {
    @Environment(ScannerBridge.self) private var scanner
    @State private var selectedItem: SidebarItem? = .dashboard
    @State private var selectedApp: VulnerableAppModel? = nil

    var body: some View {
        NavigationSplitView {
            SidebarView(selection: $selectedItem)
        } detail: {
            detailContent
                .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .navigationTitle("CVE Watch")
        .toolbar {
            ToolbarItemGroup(placement: .primaryAction) {
                toolbarContent
            }
        }
        .task {
            await scanner.loadCachedResults()
        }
    }

    @ViewBuilder
    private var detailContent: some View {
        switch selectedItem {
        case .dashboard:
            DashboardView()
        case .vulnerabilities:
            VulnerabilityListView(selectedApp: $selectedApp)
        case .allApps:
            AllAppsView()
        case .history:
            HistoryView()
        case nil:
            DashboardView()
        }
    }

    @ViewBuilder
    private var toolbarContent: some View {
        Button {
            if !scanner.isScanning {
                Task { await scanner.runScan() }
            }
        } label: {
            HStack(spacing: 6) {
                if scanner.isScanning {
                    ProgressView()
                        .controlSize(.small)
                    if scanner.scanTotal > 0 {
                        Text("\(scanner.scanCurrent)/\(scanner.scanTotal)")
                            .monospacedDigit()
                    } else {
                        Text("Scanning…")
                    }
                } else {
                    Image(systemName: "arrow.trianglehead.2.clockwise")
                    Text("Scan Now")
                }
            }
            .fixedSize()
        }
        .disabled(scanner.isScanning)
        .glassEffect(.regular.interactive())
    }
}

struct SidebarView: View {
    @Binding var selection: SidebarItem?
    @Environment(ScannerBridge.self) private var scanner

    var body: some View {
        List(SidebarItem.allCases, id: \.self, selection: $selection) { item in
            Label {
                HStack {
                    Text(item.rawValue)
                    Spacer()
                    if item == .vulnerabilities, scanner.vulnerableApps.count > 0 {
                        Text("\(scanner.vulnerableApps.count)")
                            .font(.caption2.weight(.bold))
                            .padding(.horizontal, 6)
                            .padding(.vertical, 2)
                            .background(SeverityLevel.critical.color.opacity(0.85), in: .capsule)
                            .foregroundStyle(.white)
                    }
                }
            } icon: {
                Image(systemName: item.icon)
                    .foregroundStyle(iconColor(for: item))
            }
        }
        .navigationSplitViewColumnWidth(min: 180, ideal: 220, max: 280)
    }

    private func iconColor(for item: SidebarItem) -> Color {
        switch item {
        case .dashboard: return Color(red: 0.35, green: 0.50, blue: 0.72)
        case .vulnerabilities: return SeverityLevel.critical.color
        case .allApps: return SeverityLevel.low.color
        case .history: return Color(red: 0.55, green: 0.40, blue: 0.65)
        }
    }
}
