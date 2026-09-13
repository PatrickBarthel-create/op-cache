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

@Test func digestCacheLooksAtEveryTokenOfTheOutput() {
    // Eighth adversarial round: table format, grouped seeds, lower case.
    #expect(!ProxyRunner.isCacheable("label     value\none-time password  otpauth://totp/x?secret=JBSWY3DPEHPK3PXP\n"))
    #expect(!ProxyRunner.isCacheable("JBSW Y3DP EHPK 3PXP JBSW Y3DP"))
    #expect(!ProxyRunner.isCacheable("jbswy3dpehpk3pxpjbswy3dpehpk3pxp"))
    #expect(!ProxyRunner.isCacheable("bob,JBSWY3DPEHPK3PXPJBSWY3DP"))
    #expect(!ProxyRunner.isCacheable("bob,otpauth://totp/x?secret=JBSWY3DPEHPK3PXP"))
    #expect(!ProxyRunner.isCacheable("Sommer 123456"))
    // An all-letter passphrase stays cacheable; so do keys with 0/1/8/9.
    #expect(ProxyRunner.isCacheable("correcthorsebatterystaple"))
    #expect(ProxyRunner.isCacheable("correct horse battery staple"))
    #expect(ProxyRunner.isCacheable("sk_live_0a1b8c9d0a1b8c9d0a1b"))
    #expect(ProxyRunner.isCacheable("label     value\npassword  hunter2\nusername  bob\n"))
}

@Test func tableFormatOfItemGetStaysCacheable() {
    // Ninth adversarial round: the ID line of every table-format `item get`
    // is 26 lower-case base32 characters with digits, and the lower-case rule
    // refused all of them - half of the calls on this machine.
    let table = """
    ID:          26ykszxp7l7b4fov5lcvoiiflm
    Title:       GitHub
    Vault:       Employee (5hwfmet3vgvj7khe43qiuokfu4)
    Edited:      3 weeks ago
    Version:     4
    Category:    LOGIN
    Fields:
      username:    bob
      password:    hunter2
    """
    #expect(ProxyRunner.isCacheable(table))
    // A lower-case seed at a seed length is still refused.
    #expect(!ProxyRunner.isCacheable("jbswy3dpehpk3pxpjbswy3dpehpk3pxp"))
    #expect(!ProxyRunner.isCacheable("jbswy3dpehpk3pxp"))
    // A bare 26-character lower-case run outside the ID line is a seed
    // (128 bits are 26 base32 characters): refused, whatever its length.
    #expect(!ProxyRunner.isCacheable("26ykszxp7l7b4fov5lcvoiiflm"))
    #expect(!ProxyRunner.isCacheable("jbsw y3dp ehpk 3pxp jbsw y3dp ehpk"))
    #expect(!ProxyRunner.isCacheable("jbswy3dpehpk3pxpjbsw======"))
    // The same run on the ID line of the table format is the item's ID.
    #expect(ProxyRunner.isCacheable("ID:          26ykszxp7l7b4fov5lcvoiiflm\nTitle:       X\n"))
    // In JSON the ID sits in quotes and is never a bare run.
    #expect(ProxyRunner.isCacheable(#"{"id":"26ykszxp7l7b4fov5lcvoiiflm","fields":[{"type":"CONCEALED","value":"pw"}]}"#))
}

@Test func onlyTheItemIdLineIsExemptFromTheSeedCheck() {
    // Eleventh adversarial round: a field merely labelled "ID" is not.
    #expect(ProxyRunner.isCacheable("ID:          26ykszxp7l7b4fov5lcvoiiflm\n"))
    // A field labelled "ID" sits indented under "Fields:", never at the top.
    let withIdField = "ID:          26ykszxp7l7b4fov5lcvoiiflm\nFields:\n  ID:        jbswy3dpehpk3pxpjbswy3dpeh\n"
    #expect(!ProxyRunner.isCacheable(withIdField))
    // A 32-character run on the ID line is not an item ID either.
    #expect(!ProxyRunner.isCacheable("ID: jbswy3dpehpk3pxpjbswy3dpehpk3pxp\n"))
}
