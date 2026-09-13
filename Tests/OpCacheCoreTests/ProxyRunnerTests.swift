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
