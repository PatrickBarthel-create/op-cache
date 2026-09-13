import Foundation
import Testing
@testable import OpCacheCore

@Test func digestCacheRefusesOneTimeMaterial() {
    // A JSON document with an OTP field carries the seed; a bare code is what
    // `--fields <otp-field>` returns. Neither may be stored for three days.
    let withOTP = #"{"id":"x","fields":[{"id":"o","type":"OTP","value":"otpauth://x","totp":"123456"}]}"#
    let withoutOTP = #"{"id":"x","fields":[{"id":"p","type":"CONCEALED","value":"pw"}]}"#
    #expect(!ProxyRunner.isCacheable(withOTP))
    #expect(ProxyRunner.isCacheable(withoutOTP))
    #expect(!ProxyRunner.isCacheable("123456\n"))
    #expect(!ProxyRunner.isCacheable("12345678"))
    #expect(ProxyRunner.isCacheable("12345"))
    #expect(ProxyRunner.isCacheable("hunter2-with-letters\n"))
    #expect(ProxyRunner.isCacheable("sbp_0123456789abcdef"))
}

@Test func digestCacheRefusesSeedsInEveryShape() {
    // Seventh adversarial round: `op read op://v/i/<otp field>` returns the
    // seed, `--fields … --format json` returns a field object or array.
    #expect(!ProxyRunner.isCacheable("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\n"))
    #expect(!ProxyRunner.isCacheable("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"))
    #expect(!ProxyRunner.isCacheable(#"{"id":"o","type":"OTP","value":"otpauth://x","totp":"123456"}"#))
    #expect(!ProxyRunner.isCacheable(#"[{"id":"o","type":"OTP","totp":"123456"},{"id":"u","value":"bob"}]"#))
    #expect(!ProxyRunner.isCacheable("123456,bob\n"))
    #expect(!ProxyRunner.isCacheable("123456 \n"))
    // Ordinary secrets are still cached.
    #expect(ProxyRunner.isCacheable(#"{"id":"p","type":"CONCEALED","value":"hunter2"}"#))
    #expect(ProxyRunner.isCacheable("ghp_abcdefghijklmnop0123456789"))
    #expect(ProxyRunner.isCacheable("bob,hunter2"))
}
