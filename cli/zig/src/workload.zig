// Workload identity (app/src/workload.ts). With no token configured, a job or
// a pod gets one for the JWT its platform issues, from the first of:
//
// - the file SIGILLO_OIDC_TOKEN_FILE names, such as a Kubernetes projected
//   service account token
// - SIGILLO_OIDC_TOKEN, the JWT itself (GitLab's id_tokens, Vercel, scripts)
// - GitHub Actions' ID token, in a job with `permissions: id-token: write`
//
// The server gives a token of one hour when one of the project's trust rules
// accepts the JWT. Only this command uses it: nothing is written to disk.

const std = @import("std");
const client = @import("client.zig");
const config = @import("config.zig");

pub const Env = struct {
    token_file: ?[]const u8 = null,
    token: ?[]const u8 = null,
    github_url: ?[]const u8 = null,
    github_token: ?[]const u8 = null,
};

pub fn envFromProcess(allocator: std.mem.Allocator) !Env {
    return .{
        .token_file = try nonEmptyEnvVar(allocator, "SIGILLO_OIDC_TOKEN_FILE"),
        .token = try nonEmptyEnvVar(allocator, "SIGILLO_OIDC_TOKEN"),
        .github_url = try nonEmptyEnvVar(allocator, "ACTIONS_ID_TOKEN_REQUEST_URL"),
        .github_token = try nonEmptyEnvVar(allocator, "ACTIONS_ID_TOKEN_REQUEST_TOKEN"),
    };
}

// An empty variable counts as unset, as in a CI template that leaves it blank
fn nonEmptyEnvVar(allocator: std.mem.Allocator, key: []const u8) !?[]const u8 {
    const value = try config.getEnvVarOptional(allocator, key) orelse return null;
    return if (value.len == 0) null else value;
}

// Whether this runs somewhere with a JWT to exchange
pub fn hasSource(env: Env) bool {
    return env.token_file != null or env.token != null or (env.github_url != null and env.github_token != null);
}

// A token, or why there is none; none at all without a JWT source
pub const Outcome = union(enum) {
    none,
    token: []const u8,
    failed: []const u8,
};

pub fn exchange(allocator: std.mem.Allocator, env: Env, api_url: []const u8, project: ?[]const u8) !Outcome {
    const jwt = switch (try platformJwt(allocator, env, api_url)) {
        .token => |value| value,
        else => |outcome| return outcome,
    };
    const body = if (project) |value|
        try std.fmt.allocPrint(allocator, "{{\"token\":{f},\"project\":{f}}}", .{ std.json.fmt(jwt, .{}), std.json.fmt(value, .{}) })
    else
        try std.fmt.allocPrint(allocator, "{{\"token\":{f}}}", .{std.json.fmt(jwt, .{})});
    const res = client.request(.{
        .allocator = allocator,
        .method = .POST,
        .base_url = api_url,
        .path = "/api/v0/workload/token",
        .token = null,
        .json_body = body,
    }) catch |err| return .{ .failed = try std.fmt.allocPrint(allocator, "exchanging the workload's JWT failed: {s}", .{@errorName(err)}) };
    if (res.status != 200) {
        const reason = client.parseError(allocator, res.body) orelse "no reason given";
        return .{ .failed = try std.fmt.allocPrint(allocator, "the server refused the workload's JWT ({d}): {s}", .{ res.status, reason }) };
    }
    const token = client.jsonString(allocator, res.body, "token") orelse return .{ .failed = "the server's answer has no token" };
    return .{ .token = token };
}

fn platformJwt(allocator: std.mem.Allocator, env: Env, api_url: []const u8) !Outcome {
    if (env.token_file) |path| {
        const contents = std.fs.cwd().readFileAlloc(allocator, path, 16 * 1024) catch |err|
            return .{ .failed = try std.fmt.allocPrint(allocator, "can't read SIGILLO_OIDC_TOKEN_FILE {s}: {s}", .{ path, @errorName(err) }) };
        return .{ .token = std.mem.trim(u8, contents, " \t\r\n") };
    }
    if (env.token) |value| return .{ .token = std.mem.trim(u8, value, " \t\r\n") };
    const github_url = env.github_url orelse return .none;
    const github_token = env.github_token orelse return .none;
    // The JWT names this server as its audience, which the trust rule expects
    const audience = std.mem.trimRight(u8, api_url, "/");
    const path = try std.fmt.allocPrint(allocator, "{s}audience={s}", .{
        if (std.mem.indexOfScalar(u8, github_url, '?') == null) "?" else "&",
        try percentEncode(allocator, audience),
    });
    const res = client.request(.{
        .allocator = allocator,
        .method = .GET,
        .base_url = github_url,
        .path = path,
        .token = github_token,
    }) catch |err| return .{ .failed = try std.fmt.allocPrint(allocator, "GitHub's ID token request failed: {s}", .{@errorName(err)}) };
    if (res.status != 200) {
        return .{ .failed = try std.fmt.allocPrint(allocator, "GitHub refused the ID token request ({d}): the job needs `permissions: id-token: write`", .{res.status}) };
    }
    return .{ .token = client.jsonString(allocator, res.body, "value") orelse return .{ .failed = "GitHub's answer has no ID token" } };
}

fn percentEncode(allocator: std.mem.Allocator, value: []const u8) ![]const u8 {
    var out: std.ArrayList(u8) = .empty;
    for (value) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~') {
            try out.append(allocator, c);
        } else {
            try out.print(allocator, "%{X:0>2}", .{c});
        }
    }
    return out.toOwnedSlice(allocator);
}

test "percentEncode leaves unreserved characters and escapes the rest" {
    const allocator = std.testing.allocator;
    const encoded = try percentEncode(allocator, "https://secrets.acme.com");
    defer allocator.free(encoded);
    try std.testing.expectEqualStrings("https%3A%2F%2Fsecrets.acme.com", encoded);
}

test "without a JWT source there is nothing to exchange" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const outcome = try exchange(arena.allocator(), .{ .github_url = "https://example.test" }, "https://secrets.test", null);
    try std.testing.expect(outcome == .none);
}

test "a token file that can't be read says so" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const outcome = try exchange(arena.allocator(), .{ .token_file = "/nonexistent/sigillo-token" }, "https://secrets.test", null);
    try std.testing.expectEqualStrings("can't read SIGILLO_OIDC_TOKEN_FILE /nonexistent/sigillo-token: FileNotFound", outcome.failed);
}
