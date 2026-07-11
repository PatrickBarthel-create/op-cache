public enum ChildEnvironment {
    /// Environment for the child process: the parent environment minus every
    /// configured secret name, plus the explicitly injected values. Stripping
    /// first ensures `--only` genuinely limits what the child can see, even
    /// when the parent shell already exports one of the configured names.
    public static func compose(
        base: [String: String],
        removing names: some Sequence<String>,
        injecting injected: [String: String]
    ) -> [String: String] {
        var environment = base
        for name in names {
            environment.removeValue(forKey: name)
        }
        return environment.merging(injected) { _, value in value }
    }
}
