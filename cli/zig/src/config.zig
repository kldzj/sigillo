// Scoped JSON config system for the sigillo CLI.
// Stores everything in ~/.sigillo/config.json on Unix and %APPDATA%\sigillo\config.json
// on Windows, with Doppler-style directory scopes.

const std = @import("std");
const builtin = @import("builtin");

pub const ScopedEntry = struct {
    token: ?[]const u8 = null,
    api_url: ?[]const u8 = null,
    project: ?[]const u8 = null,
    project_name: ?[]const u8 = null,
    environment: ?[]const u8 = null,
};

pub const ResolvedConfig = ScopedEntry;

pub const ScopeRecord = struct {
    scope: []const u8,
    entry: ScopedEntry,
};

pub const ConfigFile = struct {
    scopes: std.ArrayListUnmanaged(ScopeRecord) = .empty,
};

const config_dir_name = if (builtin.os.tag == .windows) "sigillo" else ".sigillo";
const config_file_name = "config.json";

pub fn configFilePath(allocator: std.mem.Allocator) ![]const u8 {
    const home = try getHomeDir(allocator);
    return std.fs.path.join(allocator, &.{ home, config_dir_name, config_file_name });
}

pub fn configDirPath(allocator: std.mem.Allocator) ![]const u8 {
    const home = try getHomeDir(allocator);
    return std.fs.path.join(allocator, &.{ home, config_dir_name });
}

pub fn readConfig(allocator: std.mem.Allocator) !ConfigFile {
    const path = try configFilePath(allocator);

    const file = std.fs.openFileAbsolute(path, .{}) catch |err| switch (err) {
        error.FileNotFound => return .{},
        else => return err,
    };
    defer file.close();

    const bytes = try file.readToEndAlloc(allocator, 1024 * 1024);

    const parsed = std.json.parseFromSliceLeaky(std.json.Value, allocator, bytes, .{}) catch return .{};

    var config: ConfigFile = .{};
    const root = switch (parsed) {
        .object => |obj| obj,
        else => return config,
    };

    const scoped_value = root.get("scoped") orelse return config;
    const scoped_object = switch (scoped_value) {
        .object => |obj| obj,
        else => return config,
    };

    var iter = scoped_object.iterator();
    while (iter.next()) |entry| {
        const scope_value = entry.value_ptr.*;
        const scope_object = switch (scope_value) {
            .object => |obj| obj,
            else => continue,
        };

        // Keys saved before scopes were realpath'd (e.g. /tmp/x on macOS) are
        // canonicalized here so resolve, setup and logout all see one key.
        var record: ScopeRecord = .{
            .scope = try normalizeScope(allocator, entry.key_ptr.*),
            .entry = .{},
        };

        if (scope_object.get("token")) |value| {
            if (value == .string) record.entry.token = value.string;
        }
        if (scope_object.get("api-url")) |value| {
            if (value == .string) record.entry.api_url = value.string;
        }
        if (scope_object.get("project")) |value| {
            if (value == .string) record.entry.project = value.string;
        }
        if (scope_object.get("project-name")) |value| {
            if (value == .string) record.entry.project_name = value.string;
        }
        if (scope_object.get("environment")) |value| {
            if (value == .string) record.entry.environment = value.string;
        }

        try appendMerged(allocator, &config, record);
    }

    return config;
}

/// Append `record`, or merge it into an existing record with the same key.
/// Later records win, matching setScope which appends new keys at the end.
fn appendMerged(allocator: std.mem.Allocator, config: *ConfigFile, record: ScopeRecord) !void {
    for (config.scopes.items) |*existing| {
        if (!std.mem.eql(u8, existing.scope, record.scope)) continue;
        try mergeEntry(allocator, &existing.entry, record.entry);
        return;
    }
    try config.scopes.append(allocator, record);
}

pub fn writeConfig(allocator: std.mem.Allocator, config: *const ConfigFile) !void {
    const dir_path = try configDirPath(allocator);
    defer allocator.free(dir_path);
    const file_path = try configFilePath(allocator);
    defer allocator.free(file_path);

    std.fs.makeDirAbsolute(dir_path) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };

    var out: std.io.Writer.Allocating = .init(allocator);
    defer out.deinit();

    var json_writer: std.json.Stringify = .{
        .writer = &out.writer,
        .options = .{ .whitespace = .indent_2 },
    };

    try json_writer.beginObject();
    try json_writer.objectField("scoped");
    try json_writer.beginObject();
    for (config.scopes.items) |record| {
        try json_writer.objectField(record.scope);
        try json_writer.beginObject();
        if (record.entry.token) |value| {
            try json_writer.objectField("token");
            try json_writer.write(value);
        }
        if (record.entry.api_url) |value| {
            try json_writer.objectField("api-url");
            try json_writer.write(value);
        }
        if (record.entry.project) |value| {
            try json_writer.objectField("project");
            try json_writer.write(value);
        }
        if (record.entry.project_name) |value| {
            try json_writer.objectField("project-name");
            try json_writer.write(value);
        }
        if (record.entry.environment) |value| {
            try json_writer.objectField("environment");
            try json_writer.write(value);
        }
        try json_writer.endObject();
    }
    try json_writer.endObject();
    try json_writer.endObject();
    try out.writer.writeByte('\n');

    const file = try std.fs.createFileAbsolute(file_path, .{ .truncate = true, .read = false, .mode = 0o600 });
    defer file.close();

    var file_writer = file.writer(&.{});
    try file_writer.interface.writeAll(out.written());
    try file_writer.interface.flush();
}

pub fn setScope(allocator: std.mem.Allocator, scope_input: []const u8, updates: ScopedEntry) !void {
    var config = try readConfig(allocator);

    const normalized_scope = try normalizeScope(allocator, scope_input);

    for (config.scopes.items) |*record| {
        if (!std.mem.eql(u8, record.scope, normalized_scope)) continue;
        try mergeEntry(allocator, &record.entry, updates);
        try writeConfig(allocator, &config);
        return;
    }

    var entry: ScopedEntry = .{};
    try mergeEntry(allocator, &entry, updates);
    try config.scopes.append(allocator, .{
        .scope = normalized_scope,
        .entry = entry,
    });
    try writeConfig(allocator, &config);
}

pub fn clearScope(allocator: std.mem.Allocator, scope_input: []const u8) !void {
    var config = try readConfig(allocator);

    const normalized_scope = try normalizeScope(allocator, scope_input);

    var index: usize = 0;
    while (index < config.scopes.items.len) : (index += 1) {
        if (!std.mem.eql(u8, config.scopes.items[index].scope, normalized_scope)) continue;

        _ = config.scopes.swapRemove(index);
        break;
    }

    try writeConfig(allocator, &config);
}

pub const default_api_url = "https://sigillo.dev";

/// A linked git worktree and the main checkout it belongs to.
pub const GitWorktree = struct {
    root: []const u8,
    main_root: []const u8,

    /// Path inside the main checkout that mirrors `path` inside this worktree.
    pub fn toMain(self: GitWorktree, allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
        return std.fs.path.join(allocator, &.{ self.main_root, relativeTo(path, self.root).? });
    }
};

/// How specific a matching scope is. Compared field by field:
/// 1. scopes inside the repo (worktree or main checkout) beat ancestors like `/`
/// 2. deeper scopes win (repo-relative depth, so worktree and main paths compare fairly)
/// 3. on a tie, the worktree's own scope beats the main checkout's
const ScopeRank = struct {
    in_repo: bool = false,
    len: usize = 0,
    worktree: bool = false,

    fn beats(self: ScopeRank, other: ?ScopeRank) bool {
        const o = other orelse return true;
        if (self.in_repo != o.in_repo) return self.in_repo;
        if (self.len != o.len) return self.len > o.len;
        return self.worktree and !o.worktree;
    }
};

/// Rank of `scope` for `cwd`, or null if it does not apply. Inside a linked
/// worktree, scopes of the main checkout apply at the same relative path, so
/// `sigillo setup` in the main repo (and its subfolders) covers every worktree.
fn scopeRank(scope: []const u8, cwd: []const u8, worktree: ?GitWorktree) ?ScopeRank {
    const wt = worktree orelse {
        return if (scopeMatches(cwd, scope)) .{ .len = scope.len } else null;
    };
    const cwd_rel = relativeTo(cwd, wt.root).?;
    if (relativeTo(scope, wt.root)) |scope_rel| {
        if (!scopeMatches(cwd_rel, scope_rel)) return null;
        return .{ .in_repo = true, .len = scope_rel.len, .worktree = true };
    }
    if (relativeTo(scope, wt.main_root)) |scope_rel| {
        if (scopeMatches(cwd_rel, scope_rel)) return .{ .in_repo = true, .len = scope_rel.len };
    }
    // Ancestors of either checkout, e.g. `/` holding the login token. Also
    // covers a worktree nested inside the main checkout (`<main>/.worktrees/x`).
    if (scopeMatches(cwd, scope) or scopeMatches(wt.main_root, scope)) return .{ .len = scope.len };
    return null;
}

/// `path` relative to `root` ("" or "/sub/dir"), or null if outside it.
fn relativeTo(path: []const u8, root: []const u8) ?[]const u8 {
    if (!scopeMatches(path, root)) return null;
    if (std.mem.eql(u8, root, "/")) return path;
    return path[root.len..];
}

// Most-specific-scope-wins accumulator. A saved token remembers the api_url of
// the record it came from so it is only ever sent to the server that issued it.
const ScopeResolution = struct {
    result: ResolvedConfig = .{},
    token_api_url: ?[]const u8 = null,
    token_rank: ?ScopeRank = null,
    api_url_rank: ?ScopeRank = null,
    project_rank: ?ScopeRank = null,
    environment_rank: ?ScopeRank = null,

    fn apply(self: *ScopeResolution, config: *const ConfigFile, cwd: []const u8, worktree: ?GitWorktree) void {
        for (config.scopes.items) |record| {
            const rank = scopeRank(record.scope, cwd, worktree) orelse continue;

            if (record.entry.token != null and rank.beats(self.token_rank)) {
                self.result.token = record.entry.token;
                self.token_api_url = record.entry.api_url;
                self.token_rank = rank;
            }
            if (record.entry.api_url != null and rank.beats(self.api_url_rank)) {
                self.result.api_url = record.entry.api_url;
                self.api_url_rank = rank;
            }
            if (record.entry.project != null and rank.beats(self.project_rank)) {
                self.result.project = record.entry.project;
                self.result.project_name = record.entry.project_name;
                self.project_rank = rank;
            }
            if (record.entry.environment != null and rank.beats(self.environment_rank)) {
                self.result.environment = record.entry.environment;
                self.environment_rank = rank;
            }
        }
    }
};

pub const Overrides = struct {
    env: ResolvedConfig = .{},
    flags: ResolvedConfig = .{},
};

pub const Resolved = struct {
    config: ResolvedConfig,
    // Set when a saved token was withheld because the api url was pointed
    // at a different server than the one the token was saved for.
    withheld_token_api_url: ?[]const u8 = null,
};

fn sameApiUrl(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, std.mem.trimRight(u8, a, "/"), std.mem.trimRight(u8, b, "/"));
}

// Env vars and flags can come from an untrusted repo (.envrc, package.json
// scripts), so an overridden api url must never receive a saved token.
// Explicit SIGILLO_TOKEN / --token are always sent as given.
fn applyOverrides(scoped: ScopeResolution, overrides: Overrides) Resolved {
    var result = scoped.result;
    const saved_token = result.token;
    const saved_token_api_url = scoped.token_api_url orelse default_api_url;

    if (overrides.env.token) |value| result.token = value;
    if (overrides.env.api_url) |value| result.api_url = value;
    if (overrides.env.project) |value| {
        result.project = value;
        result.project_name = null;
    }
    if (overrides.env.environment) |value| result.environment = value;

    if (overrides.flags.token) |value| result.token = value;
    if (overrides.flags.api_url) |value| result.api_url = value;
    if (overrides.flags.project) |value| {
        result.project = value;
        result.project_name = overrides.flags.project_name;
    }
    if (overrides.flags.environment) |value| result.environment = value;

    if (result.api_url == null) result.api_url = default_api_url;

    const token_is_saved = saved_token != null and overrides.env.token == null and overrides.flags.token == null;
    if (token_is_saved and !sameApiUrl(result.api_url.?, saved_token_api_url)) {
        result.token = null;
        return .{ .config = result, .withheld_token_api_url = saved_token_api_url };
    }
    return .{ .config = result };
}

pub fn resolve(allocator: std.mem.Allocator, cwd_input: []const u8, flags: ResolvedConfig) !ResolvedConfig {
    const config = try readConfig(allocator);
    const cwd = try normalizeScope(allocator, cwd_input);

    var scoped: ScopeResolution = .{};
    scoped.apply(&config, cwd, findGitWorktree(allocator, cwd));

    const resolved = applyOverrides(scoped, .{
        .env = .{
            .token = try getEnvVarOptional(allocator, "SIGILLO_TOKEN"),
            .api_url = try getEnvVarOptional(allocator, "SIGILLO_API_URL"),
            .project = try getEnvVarOptional(allocator, "SIGILLO_PROJECT"),
            .environment = try getEnvVarOptional(allocator, "SIGILLO_ENVIRONMENT"),
        },
        .flags = flags,
    });
    if (resolved.withheld_token_api_url) |saved_url| {
        std.debug.print(
            "warning: not sending saved token to {s}: it was saved for {s}. Use --token or SIGILLO_TOKEN, or run `sigillo login --api-url {s}`.\n",
            .{ resolved.config.api_url.?, saved_url, resolved.config.api_url.? },
        );
    }
    return resolved.config;
}

fn getHomeDir(allocator: std.mem.Allocator) ![]const u8 {
    if (builtin.os.tag == .windows) {
        return (try getEnvVarOptional(allocator, "APPDATA")) orelse
            (try getEnvVarOptional(allocator, "LOCALAPPDATA")) orelse
            (try getEnvVarOptional(allocator, "USERPROFILE")) orelse
            error.NoHomeDir;
    }

    return (try getEnvVarOptional(allocator, "HOME")) orelse
        (try getEnvVarOptional(allocator, "USERPROFILE")) orelse
        error.NoHomeDir;
}

pub fn getEnvVarOptional(allocator: std.mem.Allocator, key: []const u8) !?[]const u8 {
    return std.process.getEnvVarOwned(allocator, key) catch |err| switch (err) {
        error.EnvironmentVariableNotFound => null,
        else => err,
    };
}

pub fn getCwd(allocator: std.mem.Allocator) ![]const u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = try std.process.getCwd(&buffer);
    return allocator.dupe(u8, cwd);
}

fn normalizeScope(allocator: std.mem.Allocator, scope_input: []const u8) ![]const u8 {
    if (std.mem.eql(u8, scope_input, "/")) {
        return allocator.dupe(u8, "/");
    }

    const absolute = if (std.fs.path.isAbsolute(scope_input))
        try allocator.dupe(u8, scope_input)
    else blk: {
        const cwd = try getCwd(allocator);
        break :blk try std.fs.path.join(allocator, &.{ cwd, scope_input });
    };

    const resolved = try std.fs.path.resolve(allocator, &.{absolute});
    // Canonical spelling (e.g. /tmp -> /private/tmp) so scopes match getcwd()
    // and git's gitdir paths. Keep the lexical path if it does not exist yet.
    return std.fs.cwd().realpathAlloc(allocator, resolved) catch resolved;
}

fn scopeMatches(cwd: []const u8, scope: []const u8) bool {
    if (std.mem.eql(u8, scope, "/")) return true;
    if (!std.mem.startsWith(u8, cwd, scope)) return false;
    if (cwd.len == scope.len) return true;
    return cwd[scope.len] == std.fs.path.sep;
}

pub const ChildScope = struct {
    /// Relative path from the parent directory (e.g. "app", "services/api")
    relative_path: []const u8,
    entry: ScopedEntry,
};

/// Subfolders below `parent_dir` with a project configured, each shown with the
/// project and env that `resolve` would actually use there. Inside a linked
/// worktree, subfolders set up in the main checkout are included too.
pub fn findChildScopes(allocator: std.mem.Allocator, parent_dir: []const u8) ![]const ChildScope {
    const cfg = try readConfig(allocator);
    const parent = try normalizeScope(allocator, parent_dir);
    const worktree = findGitWorktree(allocator, parent);

    var results = std.ArrayListUnmanaged(ChildScope).empty;
    try appendChildScopes(allocator, &results, &cfg, parent, parent, worktree);
    if (worktree) |wt| {
        try appendChildScopes(allocator, &results, &cfg, try wt.toMain(allocator, parent), parent, worktree);
    }
    return results.items;
}

fn appendChildScopes(
    allocator: std.mem.Allocator,
    results: *std.ArrayListUnmanaged(ChildScope),
    cfg: *const ConfigFile,
    search_root: []const u8,
    parent: []const u8,
    worktree: ?GitWorktree,
) !void {
    outer: for (cfg.scopes.items) |record| {
        if (record.entry.project == null) continue;
        const relative = relativeTo(record.scope, search_root) orelse continue;
        const trimmed = std.mem.trimLeft(u8, relative, std.fs.path.sep_str);
        if (trimmed.len == 0) continue;
        for (results.items) |existing| {
            if (std.mem.eql(u8, existing.relative_path, trimmed)) continue :outer;
        }
        var scoped: ScopeResolution = .{};
        scoped.apply(cfg, try std.fs.path.join(allocator, &.{ parent, trimmed }), worktree);
        try results.append(allocator, .{ .relative_path = trimmed, .entry = .{
            .project = scoped.result.project,
            .project_name = scoped.result.project_name,
            .environment = scoped.result.environment,
        } });
    }
}

/// Detect if `dir` is inside a linked git worktree and return its root plus
/// the main checkout root. Null for a normal checkout or no git repo.
///
/// A linked worktree has a `.git` *file* (not directory) containing:
///   gitdir: /path/to/main-repo/.git/worktrees/<worktree-name>
/// Stripping the `.git/worktrees/<name>` suffix gives the main checkout.
pub fn findGitWorktree(allocator: std.mem.Allocator, dir: []const u8) ?GitWorktree {
    var current = dir;
    while (true) {
        const dot_git_path = std.fs.path.join(allocator, &.{ current, ".git" }) catch return null;
        const content = std.fs.cwd().readFileAlloc(allocator, dot_git_path, 4096) catch |err| switch (err) {
            error.FileNotFound => {
                const parent = std.fs.path.dirname(current) orelse return null;
                current = parent;
                continue;
            },
            // `.git` is a directory: a normal checkout, not a linked worktree.
            else => return null,
        };

        const trimmed = std.mem.trim(u8, content, " \t\r\n");
        const prefix = "gitdir: ";
        if (!std.mem.startsWith(u8, trimmed, prefix)) return null;
        // Relative when worktree.useRelativePaths=true. resolve() also turns
        // Git-for-Windows forward slashes into native separators.
        const gitdir = std.fs.path.resolve(allocator, &.{ current, trimmed[prefix.len..] }) catch return null;

        const marker = std.fs.path.sep_str ++ ".git" ++ std.fs.path.sep_str ++ "worktrees" ++ std.fs.path.sep_str;
        // Anything else (e.g. a submodule's .git/modules/<name>) is not a worktree.
        const idx = std.mem.indexOf(u8, gitdir, marker) orelse return null;
        // Git links back from `<gitdir>/gitdir` to this `.git` file. Require it,
        // so a hand-written `.git` file cannot borrow another repo's setup.
        const back_link_path = std.fs.path.join(allocator, &.{ gitdir, "gitdir" }) catch return null;
        const back_link = std.fs.cwd().readFileAlloc(allocator, back_link_path, 4096) catch return null;
        const linked = std.fs.path.resolve(allocator, &.{ gitdir, std.mem.trim(u8, back_link, " \t\r\n") }) catch return null;
        if (!samePath(allocator, linked, dot_git_path)) return null;

        const main_root = gitdir[0..idx];
        return .{
            .root = current,
            .main_root = std.fs.cwd().realpathAlloc(allocator, main_root) catch main_root,
        };
    }
}

fn samePath(allocator: std.mem.Allocator, a: []const u8, b: []const u8) bool {
    const real_a = std.fs.cwd().realpathAlloc(allocator, a) catch return false;
    const real_b = std.fs.cwd().realpathAlloc(allocator, b) catch return false;
    return std.mem.eql(u8, real_a, real_b);
}

fn mergeEntry(allocator: std.mem.Allocator, destination: *ScopedEntry, updates: ScopedEntry) !void {
    // token and api_url move together: a saved token is bound to its api url.
    if (updates.token != null or updates.api_url != null) {
        destination.token = if (updates.token) |value| try allocator.dupe(u8, value) else null;
        destination.api_url = if (updates.api_url) |value| try allocator.dupe(u8, value) else null;
    }
    if (updates.project) |value| {
        destination.project = try allocator.dupe(u8, value);
        destination.project_name = if (updates.project_name) |name| try allocator.dupe(u8, name) else null;
    }
    if (updates.environment) |value| {
        destination.environment = try allocator.dupe(u8, value);
    }
}

test "resolve prefers the longest matching scope" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var config_file: ConfigFile = .{};
    try config_file.scopes.append(allocator, .{ .scope = "/", .entry = .{ .token = "global" } });
    try config_file.scopes.append(allocator, .{ .scope = "/tmp/project", .entry = .{ .project = "project" } });

    var scoped: ScopeResolution = .{};
    scoped.apply(&config_file, "/tmp/project/subdir", null);

    try std.testing.expectEqualStrings("global", scoped.result.token.?);
    try std.testing.expectEqualStrings("project", scoped.result.project.?);
}

test "saved token is only sent to the api url it was saved with" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var config_file: ConfigFile = .{};
    try config_file.scopes.append(allocator, .{ .scope = "/", .entry = .{ .token = "saved", .api_url = "https://secrets.acme.com" } });
    var scoped: ScopeResolution = .{};
    scoped.apply(&config_file, "/repo", null);

    // No overrides: saved token goes to its own server (trailing slash ignored).
    const plain = applyOverrides(scoped, .{ .flags = .{ .api_url = "https://secrets.acme.com/" } });
    try std.testing.expectEqualStrings("saved", plain.config.token.?);
    try std.testing.expect(plain.withheld_token_api_url == null);

    // Repo-controlled SIGILLO_API_URL / --api-url must not receive the saved token.
    const via_env = applyOverrides(scoped, .{ .env = .{ .api_url = "https://evil.example" } });
    try std.testing.expect(via_env.config.token == null);
    try std.testing.expectEqualStrings("https://secrets.acme.com", via_env.withheld_token_api_url.?);
    const via_flag = applyOverrides(scoped, .{ .flags = .{ .api_url = "https://evil.example" } });
    try std.testing.expect(via_flag.config.token == null);

    // An explicit token is sent as given.
    const explicit = applyOverrides(scoped, .{ .env = .{ .api_url = "https://other.example", .token = "explicit" } });
    try std.testing.expectEqualStrings("explicit", explicit.config.token.?);

    // Token saved without api-url is bound to the default server.
    var legacy_file: ConfigFile = .{};
    try legacy_file.scopes.append(allocator, .{ .scope = "/", .entry = .{ .token = "legacy" } });
    var legacy: ScopeResolution = .{};
    legacy.apply(&legacy_file, "/repo", null);
    try std.testing.expectEqualStrings("legacy", applyOverrides(legacy, .{}).config.token.?);
    try std.testing.expect(applyOverrides(legacy, .{ .env = .{ .api_url = "http://localhost:5188" } }).config.token == null);
}

test "findGitWorktree returns null outside a linked worktree" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp_base = std.testing.tmpDir(.{});
    defer tmp_base.cleanup();
    try tmp_base.dir.makePath("repo/.git");
    try tmp_base.dir.makePath("repo/app");
    const tmp_path = try tmp_base.dir.realpathAlloc(allocator, ".");

    // Normal checkout: `.git` is a directory.
    try std.testing.expect(findGitWorktree(allocator, try std.fs.path.join(allocator, &.{ tmp_path, "repo", "app" })) == null);
}

test "findGitWorktree parses absolute and relative gitdir from a subfolder" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp_base = std.testing.tmpDir(.{});
    defer tmp_base.cleanup();
    try tmp_base.dir.makePath("main-repo/.git/worktrees/abs");
    try tmp_base.dir.makePath("main-repo/.git/worktrees/rel");
    try tmp_base.dir.makePath("abs/app");
    try tmp_base.dir.makePath("rel/app");
    const tmp_path = try tmp_base.dir.realpathAlloc(allocator, ".");
    const main_root = try std.fs.path.join(allocator, &.{ tmp_path, "main-repo" });

    const abs_gitdir = try std.fs.path.join(allocator, &.{ main_root, ".git", "worktrees", "abs" });
    try tmp_base.dir.writeFile(.{ .sub_path = "abs/.git", .data = try std.fmt.allocPrint(allocator, "gitdir: {s}\n", .{abs_gitdir}) });
    // Git writes relative paths when worktree.useRelativePaths=true.
    try tmp_base.dir.writeFile(.{ .sub_path = "rel/.git", .data = "gitdir: ../main-repo/.git/worktrees/rel\n" });

    // Without git's back link, a `.git` file is not trusted.
    try std.testing.expect(findGitWorktree(allocator, try std.fs.path.join(allocator, &.{ tmp_path, "abs", "app" })) == null);

    const abs_back = try std.fs.path.join(allocator, &.{ tmp_path, "abs", ".git" });
    try tmp_base.dir.writeFile(.{ .sub_path = "main-repo/.git/worktrees/abs/gitdir", .data = try std.fmt.allocPrint(allocator, "{s}\n", .{abs_back}) });
    try tmp_base.dir.writeFile(.{ .sub_path = "main-repo/.git/worktrees/rel/gitdir", .data = "../../../../rel/.git\n" });

    for ([_][]const u8{ "abs", "rel" }) |name| {
        const wt = findGitWorktree(allocator, try std.fs.path.join(allocator, &.{ tmp_path, name, "app" })).?;
        try std.testing.expectEqualStrings(try std.fs.path.join(allocator, &.{ tmp_path, name }), wt.root);
        try std.testing.expectEqualStrings(main_root, wt.main_root);
    }

    // A forged `.git` pointing at a real worktree entry that links elsewhere.
    try tmp_base.dir.makePath("forged");
    try tmp_base.dir.writeFile(.{ .sub_path = "forged/.git", .data = try std.fmt.allocPrint(allocator, "gitdir: {s}\n", .{abs_gitdir}) });
    try std.testing.expect(findGitWorktree(allocator, try std.fs.path.join(allocator, &.{ tmp_path, "forged" })) == null);
}

test "worktree resolution mirrors the main checkout at the same relative path" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Worktree path is shorter than the main checkout on purpose: specificity
    // must come from the repo-relative depth, not the raw path length.
    const wt: GitWorktree = .{ .root = "/wt", .main_root = "/Users/me/GitHub/repo" };

    var config_file: ConfigFile = .{};
    try config_file.scopes.append(allocator, .{ .scope = "/", .entry = .{ .token = "tok", .environment = "global-env" } });
    try config_file.scopes.append(allocator, .{ .scope = "/Users/me/GitHub/repo", .entry = .{ .project = "root_proj", .environment = "dev" } });
    try config_file.scopes.append(allocator, .{ .scope = "/Users/me/GitHub/repo/app", .entry = .{ .project = "app_proj", .environment = "dev" } });
    try config_file.scopes.append(allocator, .{ .scope = "/wt", .entry = .{ .environment = "staging" } });

    // Worktree root: main root project, worktree env override.
    var at_root: ScopeResolution = .{};
    at_root.apply(&config_file, "/wt", wt);
    try std.testing.expectEqualStrings("tok", at_root.result.token.?);
    try std.testing.expectEqualStrings("root_proj", at_root.result.project.?);
    try std.testing.expectEqualStrings("staging", at_root.result.environment.?);

    // Subfolder: main checkout's `app` scope applies; it is deeper than the
    // worktree root override, so its env wins too.
    var at_app: ScopeResolution = .{};
    at_app.apply(&config_file, "/wt/app/src", wt);
    try std.testing.expectEqualStrings("app_proj", at_app.result.project.?);
    try std.testing.expectEqualStrings("dev", at_app.result.environment.?);

    // A worktree scope at the same depth beats the main checkout.
    try config_file.scopes.append(allocator, .{ .scope = "/wt/app", .entry = .{ .environment = "prod" } });
    var overridden: ScopeResolution = .{};
    overridden.apply(&config_file, "/wt/app/src", wt);
    try std.testing.expectEqualStrings("app_proj", overridden.result.project.?);
    try std.testing.expectEqualStrings("prod", overridden.result.environment.?);
}

test "worktree resolution: repo scopes beat long ancestor scopes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const wt: GitWorktree = .{ .root = "/home/me/.worktrees/some-long-worktree-name/repo", .main_root = "/r" };
    var config_file: ConfigFile = .{};
    try config_file.scopes.append(allocator, .{ .scope = "/home/me/.worktrees", .entry = .{ .environment = "ancestor" } });
    try config_file.scopes.append(allocator, .{ .scope = "/r", .entry = .{ .project = "p", .environment = "dev" } });
    // Sibling of the main checkout with a shared prefix must not match.
    try config_file.scopes.append(allocator, .{ .scope = "/r-other", .entry = .{ .project = "wrong" } });

    var scoped: ScopeResolution = .{};
    scoped.apply(&config_file, "/home/me/.worktrees/some-long-worktree-name/repo", wt);
    try std.testing.expectEqualStrings("p", scoped.result.project.?);
    try std.testing.expectEqualStrings("dev", scoped.result.environment.?);
}

test "worktree nested inside the main checkout keeps its ancestor scopes" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const wt: GitWorktree = .{ .root = "/r/.worktrees/feat", .main_root = "/r" };
    var config_file: ConfigFile = .{};
    try config_file.scopes.append(allocator, .{ .scope = "/r/.worktrees", .entry = .{ .token = "nested" } });
    try config_file.scopes.append(allocator, .{ .scope = "/r/app", .entry = .{ .project = "app_p" } });

    var scoped: ScopeResolution = .{};
    scoped.apply(&config_file, "/r/.worktrees/feat/app", wt);
    try std.testing.expectEqualStrings("nested", scoped.result.token.?);
    try std.testing.expectEqualStrings("app_p", scoped.result.project.?);
    try std.testing.expectEqualStrings("/r/app", try wt.toMain(allocator, "/r/.worktrees/feat/app"));
    try std.testing.expectEqualStrings("/r", try wt.toMain(allocator, "/r/.worktrees/feat"));
}
