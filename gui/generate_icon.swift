#!/usr/bin/env swift
/// Generates AppIcon.icns using SwiftUI. Run: swift generate_icon.swift

import AppKit
import SwiftUI

struct IconContent: View {
    var body: some View {
        let squircle = RoundedRectangle(cornerRadius: 184, style: .continuous)

        ZStack {
            squircle
                .fill(Color(red: 0.12, green: 0.14, blue: 0.20))
                .frame(width: 824, height: 824)

            squircle
                .stroke(
                    LinearGradient(
                        stops: [
                            .init(color: .white.opacity(0.50), location: 0.0),
                            .init(color: .white.opacity(0.14), location: 0.35),
                            .init(color: .white.opacity(0.05), location: 0.65),
                            .init(color: .white.opacity(0.12), location: 1.0),
                        ],
                        startPoint: .top,
                        endPoint: .bottom
                    ),
                    lineWidth: 4
                )
                .frame(width: 824, height: 824)

            Image(systemName: "checkmark.shield.fill")
                .font(.system(size: 360, weight: .medium))
                .foregroundStyle(
                    LinearGradient(
                        colors: [
                            Color(red: 0.30, green: 0.85, blue: 0.55),
                            Color(red: 0.20, green: 0.65, blue: 0.85),
                        ],
                        startPoint: .top,
                        endPoint: .bottom
                    )
                )
        }
        .frame(width: 1024, height: 1024)
    }
}

@MainActor
func generateIcon() throws {
    let renderer = ImageRenderer(content: IconContent())
    renderer.scale = 1

    guard let cgImage = renderer.cgImage else {
        fputs("Error: failed to render icon\n", stderr)
        exit(1)
    }

    let master = NSImage(cgImage: cgImage, size: NSSize(width: 1024, height: 1024))

    let scriptURL: URL = {
        let url = URL(fileURLWithPath: CommandLine.arguments[0]).standardized
        return url.deletingLastPathComponent()
    }()

    let iconsetURL = scriptURL.appendingPathComponent("AppIcon.iconset")
    try FileManager.default.createDirectory(at: iconsetURL, withIntermediateDirectories: true)

    let variants: [(String, Int)] = [
        ("icon_16x16.png",      16),
        ("icon_16x16@2x.png",   32),
        ("icon_32x32.png",      32),
        ("icon_32x32@2x.png",   64),
        ("icon_128x128.png",   128),
        ("icon_128x128@2x.png",256),
        ("icon_256x256.png",   256),
        ("icon_256x256@2x.png",512),
        ("icon_512x512.png",   512),
        ("icon_512x512@2x.png",1024),
    ]

    print("Generating icon variants...")
    for (name, px) in variants {
        let size = NSSize(width: px, height: px)
        let resized = NSImage(size: size)
        resized.lockFocus()
        NSGraphicsContext.current?.imageInterpolation = .high
        master.draw(in: NSRect(origin: .zero, size: size))
        resized.unlockFocus()

        guard let tiff = resized.tiffRepresentation,
              let rep  = NSBitmapImageRep(data: tiff),
              let png  = rep.representation(using: .png, properties: [:])
        else { continue }
        try png.write(to: iconsetURL.appendingPathComponent(name))
        print("  \(name) (\(px)×\(px))")
    }

    let icnsURL = scriptURL.appendingPathComponent("AppIcon.icns")
    let proc = Process()
    proc.executableURL = URL(fileURLWithPath: "/usr/bin/iconutil")
    proc.arguments = ["-c", "icns", iconsetURL.path, "-o", icnsURL.path]
    try proc.run()
    proc.waitUntilExit()

    try? FileManager.default.removeItem(at: iconsetURL)
    print("✓ \(icnsURL.lastPathComponent)")
}

try MainActor.assumeIsolated {
    try generateIcon()
}
