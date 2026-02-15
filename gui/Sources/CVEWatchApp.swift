import SwiftUI

@main
struct CVEWatchApp: App {
    @State private var scannerBridge = ScannerBridge()

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(scannerBridge)
                .onChange(of: scannerBridge.isScanning) {
                    DockIconManager.update(from: scannerBridge)
                }
                .onChange(of: scannerBridge.vulnerableApps.count) {
                    DockIconManager.update(from: scannerBridge)
                }
                .onChange(of: scannerBridge.allApps.count) {
                    DockIconManager.update(from: scannerBridge)
                }
                .onAppear {
                    DockIconManager.update(from: scannerBridge)
                }
        }
        .windowStyle(.automatic)
        .windowToolbarStyle(.unified)
        .defaultSize(width: 1000, height: 700)
    }
}
