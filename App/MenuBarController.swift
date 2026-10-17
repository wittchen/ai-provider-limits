import AppKit
import SwiftUI
import ProviderLimitsCore

private struct StatusGauge {
    let color: NSColor
    /// Second tone for the 5-hour ring: darker on a light menu bar, lighter on a dark one, so it always stands out.
    let innerColor: NSColor
    let fiveHour: LimitMetric?
    /// The weekly window, or the 30-day one on Codex's free plan.
    let long: LimitMetric?

    init?(_ snapshot: ProviderUsageSnapshot) {
        fiveHour = snapshot.metrics.first { $0.id.hasSuffix("_5hour") }
        long = snapshot.metrics.first { $0.id.hasSuffix("_weekly") || $0.id.hasSuffix("_monthly") }
        guard fiveHour != nil || long != nil else { return nil }
        switch snapshot.provider {
        case .claude where snapshot.planName.contains("Team"):
            // shortcut: a Team plan is taken to be the Code Alliance login (its brand greens), add a per-account colour setting once there is a second team.
            color = NSColor(srgbRed: 0x95 / 255, green: 0xBC / 255, blue: 0x20 / 255, alpha: 1)
            innerColor = Self.contrasting(
                light: NSColor(srgbRed: 0x30 / 255, green: 0x4A / 255, blue: 0x54 / 255, alpha: 1),
                dark: NSColor(srgbRed: 0xBF / 255, green: 0xD6 / 255, blue: 0x79 / 255, alpha: 1)
            )
        case .codex:
            color = .labelColor
            innerColor = .secondaryLabelColor
        default:
            let brand = NSColor(LiquidGlassTheme.providerColor(for: snapshot.provider)).usingColorSpace(.sRGB) ?? .gray
            color = brand
            innerColor = Self.contrasting(
                light: brand.blended(withFraction: 0.4, of: .black) ?? brand,
                dark: brand.blended(withFraction: 0.4, of: .white) ?? brand
            )
        }
    }

    /// `light` is used on a light menu bar, `dark` on a dark one.
    private static func contrasting(light: NSColor, dark: NSColor) -> NSColor {
        NSColor(name: nil) { appearance in
            appearance.bestMatch(from: [.aqua, .darkAqua]) == .darkAqua ? dark : light
        }
    }
}

@MainActor
final class MenuBarController: NSObject, NSApplicationDelegate, NSPopoverDelegate {
    let state: MenuBarState
    private(set) var statusItem: NSStatusItem?
    let popover = NSPopover()
    private(set) var settingsWindow: NSWindow?
    private let refreshSnapshots: () async -> [ProviderType: ProviderUsageSnapshot]
    private let openExternalURL: (URL) -> Bool
    private let statusImage: NSImage?
    private let title: String
    private var refreshTask: Task<Void, Never>?
    private var backgroundRefreshTask: Task<Void, Never>?
    private var clockTask: Task<Void, Never>?
    private var appIcon: NSImage?
    private var contextMenu: NSMenu?
    /// Limits move slowly; a longer interval also keeps the usage endpoints from rate-limiting us.
    private static let backgroundRefreshInterval: Duration = .seconds(300)

    init(
        state: MenuBarState,
        refreshSnapshots: @escaping () async -> [ProviderType: ProviderUsageSnapshot],
        openExternalURL: @escaping (URL) -> Bool = { NSWorkspace.shared.open($0) },
        statusImage: NSImage? = nil,
        title: String = "AI Limits"
    ) {
        self.state = state
        self.refreshSnapshots = refreshSnapshots
        self.openExternalURL = openExternalURL
        self.statusImage = statusImage
        self.title = title
        super.init()
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        let item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        statusItem = item
        if let button = item.button {
            let image = statusImage ?? Self.menuBarIcon()
            image.size = NSSize(width: 18, height: 18)
            image.isTemplate = true
            appIcon = image
            button.image = image
            button.toolTip = title
            button.setAccessibilityLabel(title)
            button.target = self
            button.action = #selector(statusItemClicked(_:))
            button.sendAction(on: [.leftMouseUp, .rightMouseDown])
        }

        popover.behavior = .transient
        popover.delegate = self
        let panel = NSHostingController(rootView: MenuBarPanelRoot(
            state: state,
            onOpenSettings: { [weak self] in self?.showSettings() },
            onRefresh: { [weak self] in
                Task { await self?.refresh() }
            }
        ))
        panel.sizingOptions = [.preferredContentSize]
        popover.contentViewController = panel

        contextMenu = makeAppMenu()
        let menuBar = NSMenu()
        let appItem = NSMenuItem()
        appItem.submenu = makeAppMenu()
        menuBar.addItem(appItem)
        NSApplication.shared.mainMenu = menuBar

        observeStatusItem()
        // The reset countdowns tick every minute, between data refreshes.
        clockTask = Task { [weak self] in
            while (try? await Task.sleep(for: .seconds(60))) != nil {
                self?.renderStatusItem()
            }
        }
        backgroundRefreshTask = Task { [weak self] in
            await self?.state.loadCachedSnapshots()
            while !Task.isCancelled {
                await self?.refresh()
                do {
                    try await Task.sleep(for: Self.backgroundRefreshInterval)
                } catch {
                    return
                }
            }
        }

        if CommandLine.arguments.contains("--settings") {
            showSettings()
        }
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool { false }

    func applicationWillTerminate(_ notification: Notification) {
        refreshTask?.cancel()
        backgroundRefreshTask?.cancel()
        clockTask?.cancel()
        if let statusItem {
            NSStatusBar.system.removeStatusItem(statusItem)
        }
    }

    @objc func showSettings(_ sender: Any? = nil) {
        popover.performClose(nil)
        if settingsWindow == nil {
            let window = NSWindow(
                contentRect: NSRect(x: 0, y: 0, width: 800, height: 600),
                styleMask: [.titled, .closable, .miniaturizable, .resizable],
                backing: .buffered,
                defer: false
            )
            window.title = "Settings"
            window.isReleasedWhenClosed = false
            let hosting = NSHostingController(rootView: SettingsRoot(
                state: state,
                openExternalURL: openExternalURL
            ))
            hosting.sizingOptions = [.minSize]
            window.contentViewController = hosting
            window.contentMinSize = NSSize(width: 640, height: 480)
            window.setContentSize(NSSize(width: 800, height: 600))
            window.center()
            settingsWindow = window
        }
        NSApplication.shared.activate(ignoringOtherApps: true)
        settingsWindow?.makeKeyAndOrderFront(nil)
    }

    func popoverDidShow(_ notification: Notification) {
        refreshTask?.cancel()
        refreshTask = Task { [weak self] in
            guard let self else { return }
            await refresh()
            while !Task.isCancelled {
                do {
                    try await Task.sleep(for: .seconds(60))
                } catch {
                    return
                }
                guard popover.isShown else { return }
                await refresh()
            }
        }
    }

    func popoverDidClose(_ notification: Notification) {
        refreshTask?.cancel()
        refreshTask = nil
    }

    @objc private func statusItemClicked(_ sender: NSStatusBarButton) {
        if NSApplication.shared.currentEvent?.type == .rightMouseDown {
            popover.performClose(nil)
            if let contextMenu, let event = NSApplication.shared.currentEvent {
                NSMenu.popUpContextMenu(contextMenu, with: event, for: sender)
            }
        } else if popover.isShown {
            popover.performClose(nil)
        } else {
            popover.show(relativeTo: sender.bounds, of: sender, preferredEdge: .minY)
            popover.contentViewController?.view.window?.makeKey()
        }
    }

    private func makeAppMenu() -> NSMenu {
        let menu = NSMenu(title: title)
        let settings = NSMenuItem(title: "Settings…", action: #selector(showSettings(_:)), keyEquivalent: ",")
        settings.target = self
        menu.addItem(settings)
        menu.addItem(.separator())
        let quit = NSMenuItem(
            title: "Quit \(title)",
            action: #selector(NSApplication.terminate(_:)),
            keyEquivalent: "q"
        )
        quit.target = NSApplication.shared
        menu.addItem(quit)
        return menu
    }

    /// Re-renders the status item whenever the snapshots or visibility settings it reads change.
    private func observeStatusItem() {
        withObservationTracking {
            renderStatusItem()
        } onChange: { [weak self] in
            Task { @MainActor in self?.observeStatusItem() }
        }
    }

    private func renderStatusItem() {
        guard let button = statusItem?.button else { return }
        let gauges = state.visibleCards.compactMap(StatusGauge.init)
        let summary = state.statusTitle
        button.image = gauges.isEmpty ? appIcon : Self.gaugeImage(gauges)
        button.toolTip = summary.isEmpty ? title : summary
        button.setAccessibilityValue(summary)
    }

    /// Per account: outer ring = weekly (or 30-day) remaining, inner ring = 5-hour remaining, then both reset countdowns.
    private static func gaugeImage(_ gauges: [StatusGauge]) -> NSImage {
        let height: CGFloat = 22, ring: CGFloat = 21, textWidth: CGFloat = 37, gap: CGFloat = 8
        let segment = ring + 3 + textWidth
        let width = CGFloat(gauges.count) * segment + CGFloat(gauges.count - 1) * gap
        let attributes: [NSAttributedString.Key: Any] = [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 10, weight: .semibold),
            .foregroundColor: NSColor.labelColor
        ]
        return NSImage(size: NSSize(width: width, height: height), flipped: false) { _ in
            for (index, gauge) in gauges.enumerated() {
                let x = CGFloat(index) * (segment + gap)
                let center = NSPoint(x: x + ring / 2, y: height / 2)
                drawRing(center: center, radius: 8.75, remaining: gauge.long?.remainingPercentage, color: gauge.color)
                drawRing(center: center, radius: 4.5, remaining: gauge.fiveHour?.remainingPercentage, color: gauge.innerColor)
                let lines = [gauge.fiveHour, gauge.long].compactMap { $0.flatMap { compactCountdown(until: $0.resetsAt) } }
                let lineHeight: CGFloat = 11
                let textX = x + ring + 3
                let top = height / 2 + CGFloat(lines.count) * lineHeight / 2
                for (row, line) in lines.enumerated() {
                    let origin = NSPoint(x: textX, y: top - CGFloat(row + 1) * lineHeight)
                    (line as NSString).draw(at: origin, withAttributes: attributes)
                }
            }
            return true
        }
    }

    private static func drawRing(center: NSPoint, radius: CGFloat, remaining: Double?, color: NSColor) {
        guard let remaining else { return }
        let track = NSBezierPath()
        track.appendArc(withCenter: center, radius: radius, startAngle: 0, endAngle: 360)
        track.lineWidth = 3
        color.withAlphaComponent(0.25).setStroke()
        track.stroke()
        let fraction = min(max(remaining / 100, 0), 1)
        guard fraction > 0 else { return }
        let arc = NSBezierPath()
        arc.appendArc(withCenter: center, radius: radius, startAngle: 90, endAngle: 90 - 360 * fraction, clockwise: true)
        arc.lineWidth = 3
        color.setStroke()
        arc.stroke()
    }

    /// "42m", "1h05", "5d4h".
    private static func compactCountdown(until date: Date?) -> String? {
        guard let date else { return nil }
        let minutes = max(0, Int(date.timeIntervalSinceNow / 60))
        if minutes < 60 { return "\(minutes)m" }
        if minutes < 1_440 { return String(format: "%dh%02d", minutes / 60, minutes % 60) }
        return "\(minutes / 1_440)d\(minutes % 1_440 / 60)h"
    }

    private func refresh() async {
        guard !state.isRefreshing else { return }
        state.isRefreshing = true
        defer { state.isRefreshing = false }
        let capturedEpochs = state.captureEpochs()
        let snapshots = await refreshSnapshots()
        if !snapshots.isEmpty {
            state.applyRefreshAll(results: snapshots, capturedEpochs: capturedEpochs)
        }
        await state.refreshAdditionalClaudeAccounts()
    }

    private static func menuBarIcon() -> NSImage {
        if let icon = Bundle.main.image(forResource: "MenuBarIcon") {
            return icon
        }
        let candidates = [
            Bundle.main.url(forResource: "MenuBarIcon", withExtension: "tiff"),
            Bundle.main.url(forResource: "MenuBarIcon@2x", withExtension: "png"),
            Bundle.main.url(forResource: "MenuBarIcon", withExtension: "png")
        ]
        for case let url? in candidates {
            if let icon = NSImage(contentsOf: url) {
                return icon
            }
        }
        let image = NSImage(size: NSSize(width: 18, height: 18))
        image.lockFocus()
        NSColor.white.setFill()
        let path = NSBezierPath(ovalIn: NSRect(x: 3, y: 3, width: 12, height: 12))
        path.fill()
        image.unlockFocus()
        image.isTemplate = true
        return image
    }
}
