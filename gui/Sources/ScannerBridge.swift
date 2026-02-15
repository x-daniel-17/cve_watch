import Foundation
import SwiftUI

@Observable
@MainActor
final class ScannerBridge {
    var allApps: [AppModel] = []
    var vulnerableApps: [VulnerableAppModel] = []
    var scanHistory: [ScanHistoryEntry] = []
    var isScanning = false
    var lastScanTime: Date? = nil
    var scanError: String? = nil

    // Progress tracking
    var scanCurrent: Int = 0
    var scanTotal: Int = 0
    var currentAppName: String = ""

    private let dbReader = DatabaseReader()

    var totalCVECount: Int {
        vulnerableApps.reduce(0) { $0 + $1.cves.count }
    }

    var criticalCount: Int {
        vulnerableApps.reduce(0) { total, app in
            total + app.cves.filter { $0.severity == .critical }.count
        }
    }

    func isVulnerable(_ appName: String) -> Bool {
        vulnerableApps.contains { $0.name.lowercased() == appName.lowercased() }
    }

    func loadCachedResults() async {
        // Read from SQLite off the main thread
        let reader = dbReader
        let (history, cachedApps) = await Task.detached(priority: .userInitiated) {
            let history = reader.loadScanHistory()
            let cachedApps = reader.loadCachedApps()
            return (history, cachedApps)
        }.value

        scanHistory = history
        lastScanTime = history.first?.timestamp

        var vulnApps: [VulnerableAppModel] = []
        var allDiscovered: [AppModel] = []

        // Also read per-app CVEs off main
        let results = await Task.detached(priority: .userInitiated) {
            cachedApps.map { cached in
                let cves = reader.loadCVEs(forApp: cached.appName, version: cached.appVersion)
                let model = AppModel(
                    name: cached.appName,
                    version: cached.appVersion,
                    source: "cached",
                    bundleID: nil,
                    path: nil
                )
                return (model, cves)
            }
        }.value

        for (model, cves) in results {
            allDiscovered.append(model)
            if !cves.isEmpty {
                vulnApps.append(VulnerableAppModel(
                    name: model.name,
                    version: model.version,
                    source: model.source,
                    cves: cves
                ))
            }
        }
        if !allDiscovered.isEmpty {
            allApps = allDiscovered
        }
        if !vulnApps.isEmpty {
            vulnerableApps = vulnApps
        }
    }

    func runScan() async {
        guard !isScanning else { return }
        isScanning = true
        scanError = nil
        scanCurrent = 0
        scanTotal = 0
        currentAppName = ""

        do {
            let result = try await executePythonScan()
            allApps = result.allApps.map { $0.toModel() }
            vulnerableApps = result.vulnerableApps.map { $0.toModel() }
            lastScanTime = Date()

            // Reload history from DB
            scanHistory = dbReader.loadScanHistory()
        } catch {
            scanError = error.localizedDescription
        }

        scanCurrent = 0
        scanTotal = 0
        currentAppName = ""
        isScanning = false
    }

    private nonisolated func executePythonScan() async throws -> ScanResultJSON {
        // Run the entire blocking subprocess off the main thread
        return try await Task.detached(priority: .userInitiated) { [self] in
            let projectRoot = self.findProjectRoot()

            return try await withCheckedThrowingContinuation { continuation in
                let process = Process()
                let stdoutPipe = Pipe()
                let stderrPipe = Pipe()

                let venvPython = projectRoot + "/.venv/bin/python"
                if FileManager.default.fileExists(atPath: venvPython) {
                    process.executableURL = URL(fileURLWithPath: venvPython)
                } else {
                    process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
                }

                process.arguments = ["-m", "src.main", "--scan", "--json"]
                process.currentDirectoryURL = URL(fileURLWithPath: projectRoot)
                process.standardOutput = stdoutPipe
                process.standardError = stderrPipe

                stderrPipe.fileHandleForReading.readabilityHandler = { handle in
                    let data = handle.availableData
                    guard !data.isEmpty,
                          let text = String(data: data, encoding: .utf8) else { return }

                    for line in text.components(separatedBy: "\n") {
                        let parts = line.split(separator: ":", maxSplits: 3)
                        guard parts.count >= 4, parts[0] == "PROGRESS",
                              let current = Int(parts[1]),
                              let total = Int(parts[2]) else { continue }
                        let appName = String(parts[3])
                        Task { @MainActor in
                            self.scanCurrent = current
                            self.scanTotal = total
                            self.currentAppName = appName
                        }
                    }
                }

                process.terminationHandler = { _ in
                    stderrPipe.fileHandleForReading.readabilityHandler = nil
                    let data = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
                    guard process.terminationStatus == 0 else {
                        let errMsg = String(data: data, encoding: .utf8) ?? "Unknown error"
                        continuation.resume(throwing: ScanError.pythonError(errMsg))
                        return
                    }
                    do {
                        let result = try JSONDecoder().decode(ScanResultJSON.self, from: data)
                        continuation.resume(returning: result)
                    } catch {
                        continuation.resume(throwing: ScanError.parseError(error.localizedDescription))
                    }
                }

                do {
                    try process.run()
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }.value
    }

    private nonisolated func findProjectRoot() -> String {
        // Check for embedded project root (written by build.sh --install)
        if let resourcePath = Bundle.main.path(forResource: "project_root", ofType: "txt"),
           let embedded = try? String(contentsOfFile: resourcePath, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines),
           FileManager.default.fileExists(atPath: embedded + "/src/main.py") {
            return embedded
        }

        let execURL = Bundle.main.executableURL
        if let guiDir = execURL?.deletingLastPathComponent() {
            let candidate = guiDir.appendingPathComponent("../../..").standardized.path
            if FileManager.default.fileExists(atPath: candidate + "/src/main.py") {
                return candidate
            }
        }

        let candidates = [
            FileManager.default.currentDirectoryPath,
            FileManager.default.currentDirectoryPath + "/..",
            NSHomeDirectory() + "/Documents/cve_watch",
        ]
        for candidate in candidates {
            let url = URL(fileURLWithPath: candidate).standardized
            if FileManager.default.fileExists(atPath: url.path + "/src/main.py") {
                return url.path
            }
        }

        return FileManager.default.currentDirectoryPath
    }
}

enum ScanError: LocalizedError {
    case pythonError(String)
    case parseError(String)

    var errorDescription: String? {
        switch self {
        case .pythonError(let msg): return "Python scan failed: \(msg)"
        case .parseError(let msg): return "Failed to parse scan results: \(msg)"
        }
    }
}
