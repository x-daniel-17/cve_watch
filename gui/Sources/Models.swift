import Foundation
import SwiftUI

enum SeverityLevel: String, Codable, Hashable, Sendable {
    case critical = "CRITICAL"
    case high = "HIGH"
    case medium = "MEDIUM"
    case low = "LOW"
    case none = "NONE"
    case unknown = "UNKNOWN"

    var color: Color {
        switch self {
        case .critical: return Color(red: 0.80, green: 0.18, blue: 0.18)
        case .high: return Color(red: 0.85, green: 0.45, blue: 0.15)
        case .medium: return Color(red: 0.72, green: 0.62, blue: 0.20)
        case .low: return Color(red: 0.30, green: 0.60, blue: 0.40)
        case .none, .unknown: return .secondary
        }
    }

    var sortOrder: Int {
        switch self {
        case .critical: return 4
        case .high: return 3
        case .medium: return 2
        case .low: return 1
        case .none, .unknown: return 0
        }
    }
}

struct AppModel: Identifiable, Hashable, Sendable {
    var id: String { "\(name)-\(version)" }
    let name: String
    let version: String
    let source: String
    let bundleID: String?
    let path: String?
}

struct CVEModel: Identifiable, Hashable, Sendable {
    var id: String { cveID }
    let cveID: String
    let description: String
    let severity: SeverityLevel
    let score: Double?
    let published: Date?
    let lastModified: Date?
    let references: [String]
}

struct VulnerableAppModel: Identifiable, Hashable, Sendable {
    var id: String { "\(name)-\(version)" }
    let name: String
    let version: String
    let source: String
    let cves: [CVEModel]

    var maxSeverity: SeverityLevel {
        cves.map(\.severity).max(by: { $0.sortOrder < $1.sortOrder }) ?? .none
    }

    var maxScore: Double? {
        cves.compactMap(\.score).max()
    }
}

struct ScanHistoryEntry: Identifiable, Sendable {
    let id: Int
    let timestamp: Date
    let totalApps: Int
    let appsScanned: Int
    let totalCVEs: Int
    let criticalCount: Int
}

struct ScanResultJSON: Codable, Sendable {
    let timestamp: String
    let totalApps: Int
    let appsScanned: Int
    let allApps: [AppJSON]
    let vulnerableApps: [VulnerableAppJSON]
    let errors: [String]

    enum CodingKeys: String, CodingKey {
        case timestamp
        case totalApps = "total_apps"
        case appsScanned = "apps_scanned"
        case allApps = "all_apps"
        case vulnerableApps = "vulnerable_apps"
        case errors
    }
}

struct AppJSON: Codable, Sendable {
    let name: String
    let version: String
    let source: String
    let bundleID: String?
    let path: String?

    enum CodingKeys: String, CodingKey {
        case name, version, source
        case bundleID = "bundle_id"
        case path
    }

    func toModel() -> AppModel {
        AppModel(name: name, version: version, source: source, bundleID: bundleID, path: path)
    }
}

struct VulnerableAppJSON: Codable, Sendable {
    let name: String
    let version: String
    let source: String
    let cves: [CVEJSON]

    func toModel() -> VulnerableAppModel {
        VulnerableAppModel(
            name: name,
            version: version,
            source: source,
            cves: cves.map { $0.toModel() }
        )
    }
}

struct CVEJSON: Codable, Sendable {
    let cveID: String
    let description: String
    let severity: String
    let score: Double?
    let published: String?
    let lastModified: String?
    let references: [String]

    enum CodingKeys: String, CodingKey {
        case cveID = "cve_id"
        case description, severity, score, published
        case lastModified = "last_modified"
        case references
    }

    func toModel() -> CVEModel {
        CVEModel(
            cveID: cveID,
            description: description,
            severity: SeverityLevel(rawValue: severity) ?? .unknown,
            score: score,
            published: parseDate(published),
            lastModified: parseDate(lastModified),
            references: references
        )
    }

    private func parseDate(_ str: String?) -> Date? {
        guard let str else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let date = formatter.date(from: str) { return date }
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.date(from: str)
    }
}

struct SeverityBadge: View {
    let severity: SeverityLevel
    var size: BadgeSize = .regular

    enum BadgeSize {
        case regular, large
        var font: Font {
            switch self {
            case .regular: return .caption2.weight(.bold)
            case .large: return .caption.weight(.bold)
            }
        }
        var padding: CGFloat {
            switch self {
            case .regular: return 6
            case .large: return 8
            }
        }
    }

    var body: some View {
        Text(severity.rawValue)
            .font(size.font)
            .foregroundStyle(.white)
            .padding(.horizontal, size.padding)
            .padding(.vertical, 3)
            .background(severity.color.gradient, in: .capsule)
    }
}
