import SwiftUI

/// PoE Suite — iOS light-duty app, v1 (Phase 2 start).
/// Same scope as the Android v1: the phone's identity core
/// over the Rust poe-mobile core (UniFFI Swift bindings in
/// ../Bindings). Assembly happens in Xcode on a Mac — see
/// mobile/README.md.
@main
struct PoeSuiteApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}
