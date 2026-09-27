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

        var record: ScopeRecord = .{
            .scope = entry.key_ptr.*,
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

        try config.scopes.append(allocator, record);
    }

    return config;
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

// Longest-scope-wins accumulator. A saved token remembers the api_url of the
// record it came from so it is only ever sent to the server that issued it.
const ScopeResolution = struct {
    result: ResolvedConfig = .{},
    token_api_url: ?[]const u8 = null,
    best_token_len: usize = 0,
    best_api_url_len: usize = 0,
    best_project_len: usize = 0,
    best_environment_len: usize = 0,

    fn apply(self: *ScopeResolution, config: *const ConfigFile, path: []const u8) void {
        for (config.scopes.items) |record| {
            if (!scopeMatches(path, record.scope)) continue;

            if (record.entry.token != null and record.scope.len >= self.best_token_len) {
                self.result.token = record.entry.token;
                self.token_api_url = record.entry.api_url;
                self.best_token_len = record.scope.len;
            }
            if (record.entry.api_url != null and record.scope.len >= self.best_api_url_len) {
                self.result.api_url = record.entry.api_url;
                self.best_api_url_len = record.scope.len;
            }
            if (record.entry.project != null and record.scope.len >= self.best_project_len) {
                self.result.project = record.entry.project;
                self.result.project_name = record.entry.project_name;
                self.best_project_len = record.scope.len;
            }
            if (record.entry.environment != null and record.scope.len >= self.best_environment_len) {
                self.result.environment = record.entry.environment;
                self.best_environment_len = record.scope.len;
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
    scoped.apply(&config, cwd);
    // Worktree fallback: re-match scopes against the main repo root so
    // `sigillo setup` in the main repo applies to all its worktrees. Longer
    // (more specific) main-repo scopes override broader first-pass matches.
    if (findGitMainWorktree(allocator, cwd)) |main_root| scoped.apply(&config, main_root);

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

fn getEnvVarOptional(allocator: std.mem.Allocator, key: []const u8) !?[]const u8 {
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

    return std.fs.path.resolve(allocator, &.{absolute});
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

/// Find all configured scopes that are direct children (subfolders) of the
/// given directory. Returns scopes where the scope path starts with `parent_dir/`.
pub fn findChildScopes(allocator: std.mem.Allocator, parent_dir: []const u8) ![]const ChildScope {
    const cfg = try readConfig(allocator);
    const normalized_parent = try normalizeScope(allocator, parent_dir);

    var results = std.ArrayListUnmanaged(ChildScope).empty;

    for (cfg.scopes.items) |record| {
        // Must be strictly under parent_dir (not equal to it)
        if (record.scope.len <= normalized_parent.len) continue;
        if (!std.mem.startsWith(u8, record.scope, normalized_parent)) continue;
        if (record.scope[normalized_parent.len] != std.fs.path.sep) continue;

        // Only include scopes that have a project configured
        if (record.entry.project == null) continue;

        const relative = record.scope[normalized_parent.len + 1 ..];
        try results.append(allocator, .{
            .relative_path = relative,
            .entry = record.entry,
        });
    }

    return results.items;
}

/// Detect if `dir` is inside a git worktree. If so, return the main
/// worktree's root directory. Returns null if not in a worktree (normal
/// repo or no git repo at all).
///
/// Git worktrees have a `.git` *file* (not directory) containing:
///   gitdir: /path/to/main-repo/.git/worktrees/<worktree-name>
///
/// We parse that path and strip the `.git/worktrees/<name>` suffix to
/// recover the main repo root. This lets `resolve()` fall back to
/// scopes configured for the main repo when running inside a worktree.
pub fn findGitMainWorktree(allocator: std.mem.Allocator, dir: []const u8) ?[]const u8 {
    // Walk up from dir looking for a .git entry
    var current = dir;
    while (true) {
        const dot_git_path = std.fs.path.join(allocator, &.{ current, ".git" }) catch return null;

        // Try to open as a file first (worktree indicator)
        if (std.fs.openFileAbsolute(dot_git_path, .{})) |file| {
            defer file.close();
            const content = file.readToEndAlloc(allocator, 4096) catch return null;
            const trimmed = std.mem.trim(u8, content, " \t\r\n");

            // Must start with "gitdir: "
            const prefix = "gitdir: ";
            if (!std.mem.startsWith(u8, trimmed, prefix)) return null;
            const raw_gitdir = trimmed[prefix.len..];

            // Resolve relative gitdir paths against the directory containing
            // the .git file. Git writes relative paths when
            // worktree.useRelativePaths=true.
            const gitdir = if (std.fs.path.isAbsolute(raw_gitdir))
                raw_gitdir
            else
                std.fs.path.resolve(allocator, &.{ current, raw_gitdir }) catch return null;

            // The gitdir looks like /path/to/main-repo/.git/worktrees/<name>
            // Find "/.git/worktrees/" and extract the main repo root.
            // Also accept forward slashes for Git-for-Windows compat.
            const marker = std.fs.path.sep_str ++ ".git" ++ std.fs.path.sep_str ++ "worktrees" ++ std.fs.path.sep_str;
            if (std.mem.indexOf(u8, gitdir, marker)) |idx| {
                return allocator.dupe(u8, gitdir[0..idx]) catch return null;
            }
            // Try forward-slash variant for cross-platform Git paths
            if (comptime std.fs.path.sep != '/') {
                if (std.mem.indexOf(u8, gitdir, "/.git/worktrees/")) |idx| {
                    return allocator.dupe(u8, gitdir[0..idx]) catch return null;
                }
            }
            // gitdir exists but doesn't match the worktree pattern (e.g. submodule)
            return null;
        } else |_| {}

        // Check if .git is a directory (normal repo, not a worktree) — stop walking
        if (std.fs.openDirAbsolute(dot_git_path, .{})) |d| {
            var git_dir = d;
            git_dir.close();
            return null; // normal repo, not a worktree
        } else |_| {}

        // Walk up one level
        const parent = std.fs.path.dirname(current) orelse return null;
        if (std.mem.eql(u8, parent, current)) return null; // reached root
        current = parent;
    }
}

fn mergeEntry(allocator: std.mem.Allocator, destination: *ScopedEntry, updates: ScopedEntry) !void {
    if (updates.token) |value| {
        destination.token = try allocator.dupe(u8, value);
    }
    if (updates.api_url) |value| {
        destination.api_url = try allocator.dupe(u8, value);
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
    scoped.apply(&config_file, "/tmp/project/subdir");

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
    scoped.apply(&config_file, "/repo");

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
    legacy.apply(&legacy_file, "/repo");
    try std.testing.expectEqualStrings("legacy", applyOverrides(legacy, .{}).config.token.?);
    try std.testing.expect(applyOverrides(legacy, .{ .env = .{ .api_url = "http://localhost:5188" } }).config.token == null);
}

test "findGitMainWorktree returns null for non-git directory" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // /tmp is not a git repo, so this should return null
    try std.testing.expect(findGitMainWorktree(allocator, "/tmp") == null);
}

test "findGitMainWorktree returns null for normal git repo" {
    // The sigillo repo itself has a .git directory (not a file), so it should
    // return null — we're not in a worktree.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Use the test binary's own directory — it's inside the sigillo repo
    // which has a real .git directory.
    var buf: [std.fs.max_path_bytes]u8 = undefined;
    const cwd = std.process.getCwd(&buf) catch return;
    try std.testing.expect(findGitMainWorktree(allocator, cwd) == null);
}

test "findGitMainWorktree parses worktree .git file" {
    // Create a temp directory structure that mimics a git worktree:
    //   /tmp/xxx/main-repo/.git/worktrees/my-wt/   (directory)
    //   /tmp/xxx/my-wt/.git                         (file containing gitdir)
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp_base = std.testing.tmpDir(.{});
    defer tmp_base.cleanup();

    // Create main-repo/.git/worktrees/my-wt/ directory tree
    try tmp_base.dir.makePath("main-repo/.git/worktrees/my-wt");

    // Create the worktree directory with a .git file
    try tmp_base.dir.makePath("my-wt");

    // Get absolute path of the tmp dir
    const tmp_path = try tmp_base.dir.realpathAlloc(allocator, ".");

    // Write the .git file in the worktree
    const gitdir_target = try std.fs.path.join(allocator, &.{ tmp_path, "main-repo", ".git", "worktrees", "my-wt" });
    const git_file_content = try std.fmt.allocPrint(allocator, "gitdir: {s}\n", .{gitdir_target});
    {
        const git_file = try tmp_base.dir.createFile("my-wt/.git", .{});
        defer git_file.close();
        try git_file.writeAll(git_file_content);
    }

    const worktree_dir = try std.fs.path.join(allocator, &.{ tmp_path, "my-wt" });
    const result = findGitMainWorktree(allocator, worktree_dir);

    try std.testing.expect(result != null);
    const expected_main = try std.fs.path.join(allocator, &.{ tmp_path, "main-repo" });
    try std.testing.expectEqualStrings(expected_main, result.?);
}

test "findGitMainWorktree parses relative gitdir path" {
    // Git can write relative paths when worktree.useRelativePaths=true:
    //   gitdir: ../main-repo/.git/worktrees/my-wt
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var tmp_base = std.testing.tmpDir(.{});
    defer tmp_base.cleanup();

    try tmp_base.dir.makePath("main-repo/.git/worktrees/my-wt");
    try tmp_base.dir.makePath("my-wt");

    // Write a relative gitdir path
    {
        const git_file = try tmp_base.dir.createFile("my-wt/.git", .{});
        defer git_file.close();
        try git_file.writeAll("gitdir: ../main-repo/.git/worktrees/my-wt\n");
    }

    const tmp_path = try tmp_base.dir.realpathAlloc(allocator, ".");
    const worktree_dir = try std.fs.path.join(allocator, &.{ tmp_path, "my-wt" });
    const result = findGitMainWorktree(allocator, worktree_dir);

    try std.testing.expect(result != null);
    const expected_main = try tmp_base.dir.realpathAlloc(allocator, "main-repo");
    try std.testing.expectEqualStrings(expected_main, result.?);
}

test "worktree fallback: main repo scope overrides broad global scope" {
    // "/" sets environment=dev, "/project" sets project + environment=prod.
    // A worktree of /project at /project-feature must get prod, not dev.
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var config_file: ConfigFile = .{};
    try config_file.scopes.append(allocator, .{ .scope = "/", .entry = .{ .environment = "dev" } });
    try config_file.scopes.append(allocator, .{ .scope = "/project", .entry = .{ .project = "proj_x", .environment = "prod" } });

    var scoped: ScopeResolution = .{};
    scoped.apply(&config_file, "/project-feature");
    try std.testing.expectEqualStrings("dev", scoped.result.environment.?);
    try std.testing.expect(scoped.result.project == null);

    scoped.apply(&config_file, "/project");
    try std.testing.expectEqualStrings("proj_x", scoped.result.project.?);
    try std.testing.expectEqualStrings("prod", scoped.result.environment.?);
}

test "worktree fallback: worktree-specific scope wins over main repo" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var config_file: ConfigFile = .{};
    try config_file.scopes.append(allocator, .{ .scope = "/project", .entry = .{ .project = "proj_main", .environment = "prod" } });
    try config_file.scopes.append(allocator, .{ .scope = "/project-feature", .entry = .{ .environment = "staging" } });

    var scoped: ScopeResolution = .{};
    scoped.apply(&config_file, "/project-feature");
    try std.testing.expectEqualStrings("staging", scoped.result.environment.?);
    try std.testing.expect(scoped.result.project == null);

    // Project inherited from main repo; "/project-feature" (len 16) beats "/project" (len 8).
    scoped.apply(&config_file, "/project");
    try std.testing.expectEqualStrings("proj_main", scoped.result.project.?);
    try std.testing.expectEqualStrings("staging", scoped.result.environment.?);
}
