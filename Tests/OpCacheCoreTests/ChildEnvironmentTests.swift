import Testing
@testable import OpCacheCore

@Test func composeStripsConfiguredNamesAndInjectsSelected() {
    let base = [
        "PATH": "/usr/bin",
        "CLOUDFLARE_API_TOKEN": "leaked-from-parent-shell",
        "SUPABASE_ACCESS_TOKEN": "also-from-parent",
    ]
    let environment = ChildEnvironment.compose(
        base: base,
        removing: ["CLOUDFLARE_API_TOKEN", "SUPABASE_ACCESS_TOKEN"],
        injecting: ["SUPABASE_ACCESS_TOKEN": "fresh-from-cache"]
    )

    #expect(environment["PATH"] == "/usr/bin")
    #expect(environment["CLOUDFLARE_API_TOKEN"] == nil)
    #expect(environment["SUPABASE_ACCESS_TOKEN"] == "fresh-from-cache")
}

@Test func composeWithNothingToRemoveOrInjectKeepsBaseIntact() {
    let base = ["PATH": "/usr/bin", "HOME": "/Users/example"]
    let environment = ChildEnvironment.compose(base: base, removing: [], injecting: [:])
    #expect(environment == base)
}
