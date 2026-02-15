import Foundation
import SQLite3

final class DatabaseReader: Sendable {
    private let dbPath: String

    init() {
        let home = FileManager.default.homeDirectoryForCurrentUser
        self.dbPath = home.appendingPathComponent(".cve_watch/cache.db").path
    }

    func loadScanHistory() -> [ScanHistoryEntry] {
        guard let db = openDB() else { return [] }
        defer { sqlite3_close(db) }

        let sql = """
            SELECT id, timestamp, total_apps, apps_scanned, total_cves, critical_count
            FROM scan_history
            ORDER BY id DESC
            LIMIT 50
        """

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }

        var entries: [ScanHistoryEntry] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let id = Int(sqlite3_column_int(stmt, 0))
            let tsStr = String(cString: sqlite3_column_text(stmt, 1))
            let totalApps = Int(sqlite3_column_int(stmt, 2))
            let appsScanned = Int(sqlite3_column_int(stmt, 3))
            let totalCVEs = Int(sqlite3_column_int(stmt, 4))
            let criticalCount = Int(sqlite3_column_int(stmt, 5))

            let formatter = ISO8601DateFormatter()
            formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
            let timestamp = formatter.date(from: tsStr) ?? Date()

            entries.append(ScanHistoryEntry(
                id: id,
                timestamp: timestamp,
                totalApps: totalApps,
                appsScanned: appsScanned,
                totalCVEs: totalCVEs,
                criticalCount: criticalCount
            ))
        }
        return entries
    }

    func lastScanTime() -> Date? {
        loadScanHistory().first?.timestamp
    }

    struct CachedApp {
        let appName: String
        let appVersion: String
    }

    func loadCachedApps() -> [CachedApp] {
        guard let db = openDB() else { return [] }
        defer { sqlite3_close(db) }

        let sql = "SELECT DISTINCT app_name, app_version FROM lookup_cache"
        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }

        var apps: [CachedApp] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let name = String(cString: sqlite3_column_text(stmt, 0))
            let version = String(cString: sqlite3_column_text(stmt, 1))
            apps.append(CachedApp(appName: name, appVersion: version))
        }
        return apps
    }

    func loadCVEs(forApp name: String, version: String) -> [CVEModel] {
        guard let db = openDB() else { return [] }
        defer { sqlite3_close(db) }

        let sql = """
            SELECT cve_id, description, severity, score, published, last_modified
            FROM cve_cache
            WHERE app_name = ? AND app_version = ?
        """

        var stmt: OpaquePointer?
        guard sqlite3_prepare_v2(db, sql, -1, &stmt, nil) == SQLITE_OK else { return [] }
        defer { sqlite3_finalize(stmt) }

        sqlite3_bind_text(stmt, 1, (name as NSString).utf8String, -1, nil)
        sqlite3_bind_text(stmt, 2, (version as NSString).utf8String, -1, nil)

        var cves: [CVEModel] = []
        while sqlite3_step(stmt) == SQLITE_ROW {
            let cveID = columnText(stmt, 0)
            let desc = columnText(stmt, 1)
            let sevStr = columnText(stmt, 2)
            let score = sqlite3_column_type(stmt, 3) != SQLITE_NULL
                ? Double(sqlite3_column_double(stmt, 3))
                : nil
            let pubStr = columnOptionalText(stmt, 4)
            let modStr = columnOptionalText(stmt, 5)

            cves.append(CVEModel(
                cveID: cveID,
                description: desc,
                severity: SeverityLevel(rawValue: sevStr) ?? .unknown,
                score: score,
                published: parseDate(pubStr),
                lastModified: parseDate(modStr),
                references: []
            ))
        }
        return cves
    }

    private func openDB() -> OpaquePointer? {
        guard FileManager.default.fileExists(atPath: dbPath) else { return nil }
        var db: OpaquePointer?
        guard sqlite3_open_v2(dbPath, &db, SQLITE_OPEN_READONLY, nil) == SQLITE_OK else {
            return nil
        }
        return db
    }

    private func columnText(_ stmt: OpaquePointer?, _ col: Int32) -> String {
        if let cStr = sqlite3_column_text(stmt, col) {
            return String(cString: cStr)
        }
        return ""
    }

    private func columnOptionalText(_ stmt: OpaquePointer?, _ col: Int32) -> String? {
        guard sqlite3_column_type(stmt, col) != SQLITE_NULL else { return nil }
        if let cStr = sqlite3_column_text(stmt, col) {
            return String(cString: cStr)
        }
        return nil
    }

    private func parseDate(_ str: String?) -> Date? {
        guard let str else { return nil }
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        if let d = formatter.date(from: str) { return d }
        formatter.formatOptions = [.withInternetDateTime]
        if let d = formatter.date(from: str) { return d }
        let df = DateFormatter()
        df.dateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSSSS"
        if let d = df.date(from: str) { return d }
        df.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"
        return df.date(from: str)
    }
}
