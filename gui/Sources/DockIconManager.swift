import AppKit
import SwiftUI

@MainActor
enum DockIconManager {

    static func update(from scanner: ScannerBridge) {
        let symbolName = statusIcon(for: scanner)
        let color = statusColor(for: scanner)
        setDockIcon(symbolName: symbolName, color: color)
    }

    private static func statusIcon(for scanner: ScannerBridge) -> String {
        if scanner.isScanning { return "arrow.trianglehead.2.clockwise" }
        if scanner.allApps.isEmpty { return "shield.lefthalf.filled" }
        if scanner.criticalCount > 0 { return "exclamationmark.shield.fill" }
        if scanner.vulnerableApps.isEmpty { return "checkmark.shield.fill" }
        return "shield.lefthalf.filled"
    }

    private static func statusColor(for scanner: ScannerBridge) -> NSColor {
        if scanner.isScanning { return .systemBlue }
        if scanner.allApps.isEmpty { return .secondaryLabelColor }
        if scanner.criticalCount > 0 { return NSColor(SeverityLevel.critical.color) }
        if scanner.vulnerableApps.isEmpty { return NSColor(SeverityLevel.low.color) }
        return NSColor(SeverityLevel.high.color)
    }

    private static func setDockIcon(symbolName: String, color: NSColor) {
        let swiftUIColor = Color(nsColor: color)

        let squircle = RoundedRectangle(cornerRadius: 184, style: .continuous)

        let iconView = ZStack {
            squircle
                .fill(Color(red: 0.14, green: 0.16, blue: 0.22))
                .frame(width: 824, height: 824)

            squircle
                .stroke(
                    LinearGradient(
                        stops: [
                            .init(color: Color.white.opacity(0.45), location: 0.0),
                            .init(color: Color.white.opacity(0.12), location: 0.35),
                            .init(color: Color.white.opacity(0.05), location: 0.65),
                            .init(color: Color.white.opacity(0.10), location: 1.0),
                        ],
                        startPoint: .top,
                        endPoint: .bottom
                    ),
                    lineWidth: 3
                )
                .frame(width: 824, height: 824)

            Image(systemName: symbolName)
                .font(.system(size: 340, weight: .medium))
                .foregroundStyle(swiftUIColor)
        }
        .frame(width: 1024, height: 1024)

        let renderer = ImageRenderer(content: iconView)
        renderer.scale = 1

        guard let nsImage = renderer.nsImage else { return }
        nsImage.isTemplate = false
        NSApplication.shared.applicationIconImage = nsImage
    }
}
