// Typed HTTP client for the Sigillo API used by the Zig CLI.

const std = @import("std");
const color = @import("color.zig");
pub const api = @import("generated/sigillo-api.zig");

// Instead of std.http's zig/<version>, so the Sessions page can tell the CLI
// apart from other tools
const user_agent = "sigillo-cli/" ++ @import("build_options").version;

pub const ApiResult = struct {
    status: u16,
    body: []u8,
};

pub fn JsonResult(comptime T: type) type {
    return struct {
        status: u16,
        body: []u8,
        value: ?T,
    };
}

pub const RequestArgs = struct {
    allocator: std.mem.Allocator,
    method: std.http.Method,
    base_url: []const u8,
    path: []const u8,
    token: ?[]const u8,
    json_body: ?[]const u8 = null,
    accept: []const u8 = "application/json",
};

// A protected environment answers 403 STEP_UP_REQUIRED until its user
// approves the read with a passkey in the browser. The request is then made
// once more, for every command that reads values.
pub fn request(args: RequestArgs) !ApiResult {
    const result = try send(args);
    if (args.token == null or result.status != 403) return result;
    const environment_ids = stepUpEnvironments(args.allocator, result.body) orelse return result;
    if (!try approveInBrowser(args, environment_ids)) return result;
    return send(args);
}

fn send(args: RequestArgs) !ApiResult {
    var http_client: std.http.Client = .{ .allocator = args.allocator };
    defer http_client.deinit();
    return sendWith(&http_client, args);
}

// Every new client reads the system's CA certificates again: a loop of
// requests shares one
fn sendWith(http_client: *std.http.Client, args: RequestArgs) !ApiResult {
    const url = try std.fmt.allocPrint(args.allocator, "{s}{s}", .{ args.base_url, args.path });
    defer args.allocator.free(url);

    var response_body: std.io.Writer.Allocating = .init(args.allocator);
    defer response_body.deinit();

    var headers: std.http.Client.Request.Headers = .{ .user_agent = .{ .override = user_agent } };
    if (args.json_body != null) {
        headers.content_type = .{ .override = "application/json" };
    }

    // The token goes in extra_headers: std.http 0.15 never writes
    // privileged_headers, so a token there was not sent at all. Since
    // extra_headers would follow any redirect, never follow one with a
    // token: 3xx comes back as a status.
    const auth_header = if (args.token) |value| try std.fmt.allocPrint(args.allocator, "Bearer {s}", .{value}) else null;
    defer if (auth_header) |value| args.allocator.free(value);
    const extra_headers = [_]std.http.Header{
        .{ .name = "accept", .value = args.accept },
        .{ .name = "authorization", .value = auth_header orelse "" },
    };
    // Only a request with neither a token nor a body follows redirects, up
    // to 3, as fetch did
    const redirect_behavior: std.http.Client.Request.RedirectBehavior = if (args.token == null and args.json_body == null) .init(3) else .unhandled;
    var redirect_buffer: [8 * 1024]u8 = undefined;

    // What http_client.fetch does, which returns no response headers
    var req = try http_client.request(args.method, try std.Uri.parse(url), .{
        .headers = headers,
        .extra_headers = if (auth_header == null) extra_headers[0..1] else &extra_headers,
        .redirect_behavior = redirect_behavior,
    });
    defer req.deinit();

    if (args.json_body) |payload| {
        req.transfer_encoding = .{ .content_length = payload.len };
        var body = try req.sendBodyUnflushed(&.{});
        try body.writer.writeAll(payload);
        try body.end();
        try req.connection.?.flush();
    } else {
        try req.sendBodiless();
    }

    var response = try req.receiveHead(if (redirect_behavior == .unhandled) &.{} else &redirect_buffer);
    warnOfExpiry(args.allocator, response.head);

    const decompress_buffer: []u8 = switch (response.head.content_encoding) {
        .identity => &.{},
        .zstd => try args.allocator.alloc(u8, std.compress.zstd.default_window_len),
        .deflate, .gzip => try args.allocator.alloc(u8, std.compress.flate.max_window_len),
        .compress => return error.UnsupportedCompressionMethod,
    };
    defer args.allocator.free(decompress_buffer);
    var transfer_buffer: [64]u8 = undefined;
    var decompress: std.http.Decompress = undefined;
    const reader = response.readerDecompressing(&transfer_buffer, &decompress, decompress_buffer);
    _ = reader.streamRemaining(&response_body.writer) catch |err| switch (err) {
        error.ReadFailed => return response.bodyErr().?,
        else => |e| return e,
    };

    // Point --api-url / api-url at the final URL (e.g. https://) instead.
    const status = @intFromEnum(response.head.status);
    if (args.token != null and status >= 300 and status < 400) {
        return error.ApiUrlRedirected;
    }

    return .{
        .status = status,
        .body = try args.allocator.dupe(u8, response_body.written()),
    };
}

// ── Expiry warning ──────────────────────────────────────────────────

// The server says in Sigillo-Warning when the token or the trust rule behind
// a request stops working soon. A command makes several requests, so this
// prints the first warning only, and on stderr: stdout can be a download or
// a command's output.
pub var expiry_warned = false;

fn warnOfExpiry(allocator: std.mem.Allocator, head: std.http.Client.Response.Head) void {
    if (expiry_warned) return;
    var headers = head.iterateHeaders();
    while (headers.next()) |header| {
        if (!std.ascii.eqlIgnoreCase(header.name, "sigillo-warning")) continue;
        const message = (expiryWarning(allocator, header.value) catch return) orelse continue;
        expiry_warned = true;
        const stderr = std.fs.File.stderr().deprecatedWriter();
        color.yellow(stderr, "warning") catch {};
        stderr.print(": {s}\n", .{message}) catch {};
        return;
    }
}

// The warning for a header like `token-expiry; expires=2026-10-13T12:00:00Z;
// days=3`, cleaned for the terminal, or null for one it can't read
pub fn expiryWarning(allocator: std.mem.Allocator, value: []const u8) !?[]const u8 {
    const Kind = enum { @"token-expiry", @"rule-expiry", @"token-regenerated" };
    var items = std.mem.splitScalar(u8, value, ';');
    const kind = std.meta.stringToEnum(Kind, std.mem.trim(u8, items.first(), " \t")) orelse return null;
    var expires: ?[]const u8 = null;
    var days: ?u32 = null;
    while (items.next()) |item| {
        const pair = std.mem.trim(u8, item, " \t");
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse return null;
        if (std.mem.eql(u8, pair[0..eq], "expires")) expires = pair[eq + 1 ..];
        if (std.mem.eql(u8, pair[0..eq], "days")) days = std.fmt.parseInt(u32, pair[eq + 1 ..], 10) catch return null;
    }
    const expiry = expires orelse return null;
    if (expiry.len < 10) return null;
    const date = try color.plain(allocator, expiry[0..10]);
    const left = days orelse return null;
    const when = if (left <= 1) "within a day" else try std.fmt.allocPrint(allocator, "in {d} days", .{left});
    return switch (kind) {
        .@"token-expiry" => try std.fmt.allocPrint(allocator, "this API token expires on {s} ({s}). Regenerate it on the project's Machines tab; the old value then keeps working for up to 7 days.", .{ date, when }),
        .@"rule-expiry" => try std.fmt.allocPrint(allocator, "the trust rule this workload uses expires on {s} ({s}). An org admin renews it on the project's Machines tab.", .{ date, when }),
        .@"token-regenerated" => try std.fmt.allocPrint(allocator, "this token was regenerated; this value stops working on {s} ({s}). Switch to the new value.", .{ date, when }),
    };
}

pub fn parseJsonResult(comptime T: type, args: RequestArgs) !JsonResult(T) {
    const response = try request(args);
    if (response.status < 200 or response.status >= 300) {
        return .{ .status = response.status, .body = response.body, .value = null };
    }

    return .{
        .status = response.status,
        .body = response.body,
        .value = try std.json.parseFromSliceLeaky(T, args.allocator, response.body, .{ .ignore_unknown_fields = true }),
    };
}

// Unset optional fields are left out: the API accepts a missing field, not null
fn jsonBody(allocator: std.mem.Allocator, value: anytype) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{f}", .{std.json.fmt(value, .{ .emit_null_optional_fields = false })});
}

// The server's message, cleaned for the terminal, since every caller prints it
pub fn parseError(allocator: std.mem.Allocator, body: []const u8) ?[]const u8 {
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return null;

    const object = switch (parsed) {
        .object => |value| value,
        else => return null,
    };

    if (object.get("error_description")) |value| {
        if (value == .string) return color.plain(allocator, value.string) catch null;
    }
    if (object.get("error")) |value| {
        if (value == .string) return color.plain(allocator, value.string) catch null;
    }
    return null;
}

pub fn jsonString(allocator: std.mem.Allocator, body: []const u8, field: []const u8) ?[]const u8 {
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return null;

    const object = switch (parsed) {
        .object => |value| value,
        else => return null,
    };

    const value = object.get(field) orelse return null;
    return switch (value) {
        .string => |string| string,
        else => null,
    };
}

pub const NamedItem = struct {
    id: []const u8,
    name: []const u8,
};

pub fn jsonNamedArray(allocator: std.mem.Allocator, body: []const u8, field: []const u8) ![]NamedItem {
    var result = std.ArrayListUnmanaged(NamedItem).empty;

    const parsed = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return result.toOwnedSlice(allocator);
    const root = switch (parsed) {
        .object => |obj| obj,
        else => return result.toOwnedSlice(allocator),
    };
    const arr_val = root.get(field) orelse return result.toOwnedSlice(allocator);
    const arr = switch (arr_val) {
        .array => |a| a,
        else => return result.toOwnedSlice(allocator),
    };
    for (arr.items) |item| {
        const obj = switch (item) {
            .object => |o| o,
            else => continue,
        };
        const id_val = obj.get("id") orelse continue;
        const name_val = obj.get("name") orelse continue;
        const id = switch (id_val) {
            .string => |s| s,
            else => continue,
        };
        const name = switch (name_val) {
            .string => |s| s,
            else => continue,
        };
        try result.append(allocator, .{ .id = id, .name = name });
    }
    return result.toOwnedSlice(allocator);
}

pub fn jsonInt(allocator: std.mem.Allocator, body: []const u8, field: []const u8) ?i64 {
    const parsed = std.json.parseFromSliceLeaky(std.json.Value, allocator, body, .{}) catch return null;

    const object = switch (parsed) {
        .object => |value| value,
        else => return null,
    };

    const value = object.get(field) orelse return null;
    return switch (value) {
        .integer => |integer| integer,
        else => null,
    };
}

pub const GetMeArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
};

pub fn getMe(args: GetMeArgs) !JsonResult(api.MeResponse) {
    return parseJsonResult(api.MeResponse, .{
        .allocator = args.allocator,
        .method = .GET,
        .base_url = args.api_url,
        .path = "/api/v0/me",
        .token = args.token,
    });
}

pub const ListOrgsArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
};

pub fn listOrgs(args: ListOrgsArgs) !JsonResult(api.OrgListResponse) {
    return parseJsonResult(api.OrgListResponse, .{
        .allocator = args.allocator,
        .method = .GET,
        .base_url = args.api_url,
        .path = "/api/v0/orgs",
        .token = args.token,
    });
}

pub const CreateOrgArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    name: []const u8,
};

pub fn createOrg(args: CreateOrgArgs) !JsonResult(api.OrgMutationResponse) {
    const body = try jsonBody(args.allocator, api.OrgCreateRequest{ .name = args.name });
    return parseJsonResult(api.OrgMutationResponse, .{
        .allocator = args.allocator,
        .method = .POST,
        .base_url = args.api_url,
        .path = "/api/v0/orgs",
        .token = args.token,
        .json_body = body,
    });
}

pub const ListProjectsArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    org_id: ?[]const u8 = null,
};

pub fn listProjects(args: ListProjectsArgs) !JsonResult(api.ProjectListResponse) {
    const path = if (args.org_id) |org_id|
        try std.fmt.allocPrint(args.allocator, "/api/v0/projects?orgId={s}", .{org_id})
    else
        "/api/v0/projects";
    return parseJsonResult(api.ProjectListResponse, .{
        .allocator = args.allocator,
        .method = .GET,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
    });
}

pub const GetProjectArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    project_id: []const u8,
};

pub fn getProject(args: GetProjectArgs) !JsonResult(api.ProjectSummary) {
    const path = try std.fmt.allocPrint(args.allocator, "/api/v0/projects/{s}", .{args.project_id});
    return parseJsonResult(api.ProjectSummary, .{
        .allocator = args.allocator,
        .method = .GET,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
    });
}

pub const CreateProjectArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    org_id: []const u8,
    name: []const u8,
};

pub fn createProject(args: CreateProjectArgs) !JsonResult(api.ProjectMutationResponse) {
    const body = try jsonBody(args.allocator, api.ProjectCreateRequest{ .orgId = args.org_id, .name = args.name });
    return parseJsonResult(api.ProjectMutationResponse, .{
        .allocator = args.allocator,
        .method = .POST,
        .base_url = args.api_url,
        .path = "/api/v0/projects",
        .token = args.token,
        .json_body = body,
    });
}

pub const UpdateProjectArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    project_id: []const u8,
    name: []const u8,
};

pub fn updateProject(args: UpdateProjectArgs) !JsonResult(api.ProjectMutationResponse) {
    const path = try std.fmt.allocPrint(args.allocator, "/api/v0/projects/{s}", .{args.project_id});
    const body = try jsonBody(args.allocator, api.ProjectUpdateRequest{ .name = args.name });
    return parseJsonResult(api.ProjectMutationResponse, .{
        .allocator = args.allocator,
        .method = .PATCH,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
        .json_body = body,
    });
}

pub const DeleteProjectArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    project_id: []const u8,
};

pub fn deleteProject(args: DeleteProjectArgs) !JsonResult(api.ProjectDeleteResponse) {
    const path = try std.fmt.allocPrint(args.allocator, "/api/v0/projects/{s}", .{args.project_id});
    return parseJsonResult(api.ProjectDeleteResponse, .{
        .allocator = args.allocator,
        .method = .DELETE,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
    });
}

pub const ListEnvironmentsArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    project_id: []const u8,
};

pub fn listEnvironments(args: ListEnvironmentsArgs) !JsonResult(api.EnvironmentListResponse) {
    const path = try std.fmt.allocPrint(args.allocator, "/api/v0/projects/{s}/environments", .{args.project_id});
    return parseJsonResult(api.EnvironmentListResponse, .{
        .allocator = args.allocator,
        .method = .GET,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
    });
}

pub const GetEnvironmentArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    project_id: []const u8,
    environment_id: []const u8,
};

pub fn getEnvironment(args: GetEnvironmentArgs) !JsonResult(api.EnvironmentSummary) {
    const path = try std.fmt.allocPrint(args.allocator, "/api/v0/projects/{s}/environments/{s}", .{ args.project_id, args.environment_id });
    return parseJsonResult(api.EnvironmentSummary, .{
        .allocator = args.allocator,
        .method = .GET,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
    });
}

pub const CreateEnvironmentArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    project_id: []const u8,
    name: []const u8,
    slug: []const u8,
};

pub fn createEnvironment(args: CreateEnvironmentArgs) !JsonResult(api.EnvironmentMutationResponse) {
    const path = try std.fmt.allocPrint(args.allocator, "/api/v0/projects/{s}/environments", .{args.project_id});
    const body = try jsonBody(args.allocator, api.EnvironmentCreateRequest{ .name = args.name, .slug = args.slug });
    return parseJsonResult(api.EnvironmentMutationResponse, .{
        .allocator = args.allocator,
        .method = .POST,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
        .json_body = body,
    });
}

pub const UpdateEnvironmentArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    project_id: []const u8,
    environment_id: []const u8,
    name: ?[]const u8 = null,
    slug: ?[]const u8 = null,
};

pub fn updateEnvironment(args: UpdateEnvironmentArgs) !JsonResult(api.EnvironmentMutationResponse) {
    const path = try std.fmt.allocPrint(args.allocator, "/api/v0/projects/{s}/environments/{s}", .{ args.project_id, args.environment_id });
    const body = try jsonBody(args.allocator, api.EnvironmentUpdateRequest{ .name = args.name, .slug = args.slug });
    return parseJsonResult(api.EnvironmentMutationResponse, .{
        .allocator = args.allocator,
        .method = .PATCH,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
        .json_body = body,
    });
}

pub const DeleteEnvironmentArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    project_id: []const u8,
    environment_id: []const u8,
};

pub fn deleteEnvironment(args: DeleteEnvironmentArgs) !JsonResult(api.EnvironmentDeleteResponse) {
    const path = try std.fmt.allocPrint(args.allocator, "/api/v0/projects/{s}/environments/{s}", .{ args.project_id, args.environment_id });
    return parseJsonResult(api.EnvironmentDeleteResponse, .{
        .allocator = args.allocator,
        .method = .DELETE,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
    });
}

pub const ListSecretsArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    project_id: []const u8,
    environment_id: []const u8,
};

pub fn listSecrets(args: ListSecretsArgs) !JsonResult(api.SecretListResponse) {
    const path = try std.fmt.allocPrint(args.allocator, "/api/v0/projects/{s}/environments/{s}/secrets", .{ args.project_id, args.environment_id });
    return parseJsonResult(api.SecretListResponse, .{
        .allocator = args.allocator,
        .method = .GET,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
    });
}

pub const GetSecretArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    project_id: []const u8,
    environment_id: []const u8,
    name: []const u8,
};

pub fn getSecret(args: GetSecretArgs) !JsonResult(api.SecretValueResponse) {
    const path = try std.fmt.allocPrint(args.allocator, "/api/v0/projects/{s}/environments/{s}/secrets/{s}", .{ args.project_id, args.environment_id, args.name });
    return parseJsonResult(api.SecretValueResponse, .{
        .allocator = args.allocator,
        .method = .GET,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
    });
}

pub const SetSecretArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    project_id: []const u8,
    environment_id: []const u8,
    name: []const u8,
    value: []const u8,
};

pub fn setSecret(args: SetSecretArgs) !JsonResult(api.SecretMutationResponse) {
    const path = try std.fmt.allocPrint(args.allocator, "/api/v0/projects/{s}/environments/{s}/secrets", .{ args.project_id, args.environment_id });
    const body = try jsonBody(args.allocator, api.SecretSetRequest{ .name = args.name, .value = args.value });
    return parseJsonResult(api.SecretMutationResponse, .{
        .allocator = args.allocator,
        .method = .POST,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
        .json_body = body,
    });
}

pub const DeleteSecretArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    project_id: []const u8,
    environment_id: []const u8,
    name: []const u8,
};

pub fn deleteSecret(args: DeleteSecretArgs) !JsonResult(api.SecretDeleteResponse) {
    const path = try std.fmt.allocPrint(args.allocator, "/api/v0/projects/{s}/environments/{s}/secrets/{s}", .{ args.project_id, args.environment_id, args.name });
    return parseJsonResult(api.SecretDeleteResponse, .{
        .allocator = args.allocator,
        .method = .DELETE,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
    });
}

pub const DownloadSecretsArgs = struct {
    allocator: std.mem.Allocator,
    api_url: []const u8,
    token: []const u8,
    project_id: []const u8,
    environment_id: []const u8,
    format: []const u8,
};

pub fn downloadSecrets(args: DownloadSecretsArgs) !ApiResult {
    const path = try std.fmt.allocPrint(args.allocator, "/api/v0/projects/{s}/environments/{s}/secrets/download?format={s}", .{ args.project_id, args.environment_id, args.format });
    return request(.{
        .allocator = args.allocator,
        .method = .GET,
        .base_url = args.api_url,
        .path = path,
        .token = args.token,
        .accept = "*/*",
    });
}

// ── Step-up ─────────────────────────────────────────────────────────

// How often the CLI asks whether the read was approved, and how long it
// waits at most: the server's requests last 10 minutes, and it says when one
// expired, so this clock only ends a wait the server never answers
pub var step_up_poll_ms: u64 = 2000;
const step_up_wait_ms: i64 = 11 * 60 * 1000;

fn stepUpEnvironments(allocator: std.mem.Allocator, body: []const u8) ?[]const []const u8 {
    const Denied = struct { code: []const u8 = "", environmentIds: []const []const u8 = &.{} };
    const parsed = std.json.parseFromSliceLeaky(Denied, allocator, body, .{ .ignore_unknown_fields = true }) catch return null;
    if (!std.mem.eql(u8, parsed.code, "STEP_UP_REQUIRED") or parsed.environmentIds.len == 0) return null;
    return parsed.environmentIds;
}

// Opens a request for this login, shows where to approve it and the code to
// type there (never part of the link), and waits for the approval
fn approveInBrowser(args: RequestArgs, environment_ids: []const []const u8) !bool {
    const stderr = std.fs.File.stderr().deprecatedWriter();
    const opened = try send(.{
        .allocator = args.allocator,
        .method = .POST,
        .base_url = args.base_url,
        .path = "/api/v0/step-up",
        .token = args.token,
        .json_body = try jsonBody(args.allocator, .{ .environmentIds = environment_ids }),
    });
    const Opened = struct { id: []const u8, userCode: []const u8, approveUrl: []const u8 };
    const request_info = (if (opened.status == 200) std.json.parseFromSliceLeaky(Opened, args.allocator, opened.body, .{ .ignore_unknown_fields = true }) catch null else null) orelse {
        const message = parseError(args.allocator, opened.body) orelse "unknown error";
        try color.err(stderr, "error");
        try stderr.print(": could not ask for an approval ({d}): {s}\n", .{ opened.status, message });
        return false;
    };

    try stderr.writeAll("This environment is protected: approve with your passkey.\n  Open ");
    try color.cyan(stderr, try color.plain(args.allocator, request_info.approveUrl));
    try stderr.writeAll(" and enter ");
    try color.bold(stderr, try color.plain(args.allocator, request_info.userCode));
    try stderr.writeAll("\n");
    try color.dim(stderr, "Waiting for your approval...\n");

    // A check that fails on the way (a dropped connection, 429, 5xx) doesn't
    // end the wait; the server refusing it (401, 403, 404) does
    const status_path = try std.fmt.allocPrint(args.allocator, "/api/v0/step-up/{s}", .{request_info.id});
    var http_client: std.http.Client = .{ .allocator = args.allocator };
    defer http_client.deinit();
    var last_failure: ?[]const u8 = null;
    const deadline = std.time.milliTimestamp() + step_up_wait_ms;
    while (std.time.milliTimestamp() < deadline) {
        std.Thread.sleep(step_up_poll_ms * std.time.ns_per_ms);
        const polled = sendWith(&http_client, .{ .allocator = args.allocator, .method = .GET, .base_url = args.base_url, .path = status_path, .token = args.token }) catch |err| {
            last_failure = @errorName(err);
            continue;
        };
        switch (polled.status) {
            200 => {
                const status = jsonString(args.allocator, polled.body, "status") orelse "";
                if (std.mem.eql(u8, status, "approved")) {
                    try color.green(stderr, "✔");
                    try stderr.writeAll(" Approved for 15 minutes\n");
                    return true;
                }
                if (!std.mem.eql(u8, status, "pending")) break;
                last_failure = null;
            },
            401, 403, 404 => {
                try color.err(stderr, "error");
                try stderr.print(": checking the approval failed ({d}): {s}\n", .{ polled.status, parseError(args.allocator, polled.body) orelse "unknown error" });
                return false;
            },
            else => last_failure = try std.fmt.allocPrint(args.allocator, "{d}: {s}", .{ polled.status, parseError(args.allocator, polled.body) orelse "unknown error" }),
        }
    }
    try color.err(stderr, "error");
    if (last_failure) |failure| {
        try stderr.print(": couldn't check the approval ({s}): run the command again\n", .{failure});
    } else {
        try stderr.writeAll(": the approval expired: run the command again\n");
    }
    return false;
}
