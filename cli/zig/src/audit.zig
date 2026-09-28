// Checks for `sigillo audit verify`. Each environment has two hash chains on
// the server (see app/src/audit.ts): its secret changes and the reads of its
// values. The server hands out every row with the preimage it rebuilt from
// the database, so checking a chain needs only SHA-256 and Ed25519:
//
//   hash_n = SHA-256(hash_(n-1) as hex ++ preimage_n), hash_0 = 64 zeros
//   signature_n = Ed25519 signature of the 32 bytes of hash_n
//
// A chain that checks out can still have lost its newest rows, so the CLI is
// a witness: it keeps the last head it saw of each chain, and the server's
// signing key, in ~/.sigillo/audit.json, and compares them the next time.

const std = @import("std");
const config = @import("config.zig");

const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const ChainRow = struct {
    seq: u64,
    hash: []const u8,
    signature: []const u8,
    preimage: []const u8,
};

pub const AuditResponse = struct {
    environmentId: []const u8,
    publicKey: []const u8,
    // adopted: rows from before the chain, which the server signed as it found them
    events: struct { rows: []const ChainRow, outside: u64, adopted: u64 = 0 },
    reads: struct { rows: []const ChainRow },
};

pub const Head = struct {
    seq: u64,
    hash: []const u8,
};

pub const Check = union(enum) {
    // The newest row, null for an empty chain
    ok: ?Head,
    problem: []const u8,
};

const zero_hash = "0" ** 64;

pub fn verifyChain(allocator: std.mem.Allocator, public_key: []const u8, rows: []const ChainRow) !Check {
    var key_bytes: [Ed25519.PublicKey.encoded_length]u8 = undefined;
    decodeBase64(&key_bytes, public_key) catch return .{ .problem = "the server's signing key is not an Ed25519 key" };
    const key = Ed25519.PublicKey.fromBytes(key_bytes) catch return .{ .problem = "the server's signing key is not an Ed25519 key" };

    var prev: []const u8 = zero_hash;
    for (rows, 1..) |row, seq| {
        if (row.seq != seq) return .{ .problem = try std.fmt.allocPrint(allocator, "row {d} is missing", .{seq}) };

        var digest: [Sha256.digest_length]u8 = undefined;
        var hasher = Sha256.init(.{});
        hasher.update(prev);
        hasher.update(row.preimage);
        hasher.final(&digest);
        const hex = std.fmt.bytesToHex(digest, .lower);
        if (!std.mem.eql(u8, &hex, row.hash)) {
            return .{ .problem = try std.fmt.allocPrint(allocator, "row {d} does not match its hash", .{seq}) };
        }

        var signature_bytes: [Ed25519.Signature.encoded_length]u8 = undefined;
        const signed = blk: {
            decodeBase64(&signature_bytes, row.signature) catch break :blk false;
            Ed25519.Signature.fromBytes(signature_bytes).verify(&digest, key) catch break :blk false;
            break :blk true;
        };
        if (!signed) return .{ .problem = try std.fmt.allocPrint(allocator, "row {d} has an invalid signature", .{seq}) };
        prev = row.hash;
    }
    if (rows.len == 0) return .{ .ok = null };
    return .{ .ok = .{ .seq = rows.len, .hash = rows[rows.len - 1].hash } };
}

fn decodeBase64(out: []u8, input: []const u8) !void {
    const decoder = std.base64.standard.Decoder;
    if (try decoder.calcSizeForSlice(input) != out.len) return error.InvalidLength;
    try decoder.decode(out, input);
}

// The head saved last time must still be in the chain, unchanged: otherwise
// rows were removed, or history was rewritten and signed again by the server.
pub fn compareWithWitness(allocator: std.mem.Allocator, seen: ?Head, rows: []const ChainRow) !?[]const u8 {
    const head = seen orelse return null;
    if (rows.len < head.seq) {
        return try std.fmt.allocPrint(allocator, "has {d} rows, but had {d} when you last verified it", .{ rows.len, head.seq });
    }
    if (!std.mem.eql(u8, rows[head.seq - 1].hash, head.hash)) {
        return try std.fmt.allocPrint(allocator, "row {d} changed since you last verified it", .{head.seq});
    }
    return null;
}

// ── Witness file ────────────────────────────────────────────────────

pub const Witness = struct {
    public_key: []const u8,
    events: ?Head = null,
    reads: ?Head = null,
    verified_at: i64 = 0,
};

const Witnesses = std.json.ArrayHashMap(Witness);

fn witnessPath(allocator: std.mem.Allocator) ![]const u8 {
    return std.fs.path.join(allocator, &.{ try config.configDirPath(allocator), "audit.json" });
}

fn readWitnesses(allocator: std.mem.Allocator) !Witnesses {
    const file = std.fs.openFileAbsolute(try witnessPath(allocator), .{}) catch |err| switch (err) {
        error.FileNotFound => return .{},
        else => return err,
    };
    defer file.close();
    const bytes = try file.readToEndAlloc(allocator, 16 * 1024 * 1024);
    return std.json.parseFromSliceLeaky(Witnesses, allocator, bytes, .{ .ignore_unknown_fields = true });
}

// Witnesses are kept per server and environment
// Keyed by what you asked to check, not by what the server answers: an
// environment recreated in the database under a new id, with its history
// moved over and adopted again, still meets the head seen before
pub fn witnessKey(allocator: std.mem.Allocator, api_url: []const u8, project: []const u8, environment: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s} {s} {s}", .{ std.mem.trimRight(u8, api_url, "/"), project, environment });
}

// How witnesses were keyed before: by the environment id the server sent
pub fn legacyWitnessKey(allocator: std.mem.Allocator, api_url: []const u8, environment_id: []const u8) ![]const u8 {
    return std.fmt.allocPrint(allocator, "{s} {s}", .{ api_url, environment_id });
}

pub fn readWitness(allocator: std.mem.Allocator, key: []const u8) !?Witness {
    const witnesses = try readWitnesses(allocator);
    return witnesses.map.get(key);
}

pub fn writeWitness(allocator: std.mem.Allocator, key: []const u8, witness: Witness) !void {
    var witnesses = try readWitnesses(allocator);
    try witnesses.map.put(allocator, key, witness);

    std.fs.makeDirAbsolute(try config.configDirPath(allocator)) catch |err| switch (err) {
        error.PathAlreadyExists => {},
        else => return err,
    };
    const bytes = try std.fmt.allocPrint(allocator, "{f}\n", .{std.json.fmt(witnesses, .{ .whitespace = .indent_2 })});
    // Written next to it and renamed over it, so a crash or a second run at
    // the same time never leaves half a file
    const path = try witnessPath(allocator);
    const tmp_path = try std.fmt.allocPrint(allocator, "{s}.{x}.tmp", .{ path, std.crypto.random.int(u64) });
    {
        const file = try std.fs.createFileAbsolute(tmp_path, .{ .truncate = true, .mode = 0o600 });
        defer file.close();
        try file.writeAll(bytes);
    }
    std.fs.renameAbsolute(tmp_path, path) catch |err| {
        std.fs.deleteFileAbsolute(tmp_path) catch {};
        return err;
    };
}

// ── Tests ───────────────────────────────────────────────────────────

const TestChain = struct {
    public_key: []const u8,
    rows: []ChainRow,
};

// Builds a chain the way the server does, signed with a fixed test key
fn testChain(allocator: std.mem.Allocator, preimages: []const []const u8) !TestChain {
    const pair = try Ed25519.KeyPair.generateDeterministic([_]u8{7} ** 32);
    const encoder = std.base64.standard.Encoder;
    const rows = try allocator.alloc(ChainRow, preimages.len);
    var prev: []const u8 = zero_hash;
    for (preimages, 0..) |preimage, i| {
        var digest: [Sha256.digest_length]u8 = undefined;
        var hasher = Sha256.init(.{});
        hasher.update(prev);
        hasher.update(preimage);
        hasher.final(&digest);
        const hash = try allocator.dupe(u8, &std.fmt.bytesToHex(digest, .lower));
        const signature = (try pair.sign(&digest, null)).toBytes();
        rows[i] = .{
            .seq = i + 1,
            .hash = hash,
            .signature = encoder.encode(try allocator.alloc(u8, encoder.calcSize(signature.len)), &signature),
            .preimage = preimage,
        };
        prev = hash;
    }
    const key = pair.public_key.toBytes();
    return .{
        .public_key = encoder.encode(try allocator.alloc(u8, encoder.calcSize(key.len)), &key),
        .rows = rows,
    };
}

fn expectProblem(expected: []const u8, check: Check) !void {
    switch (check) {
        .ok => return error.TestExpectedProblem,
        .problem => |problem| try std.testing.expectEqualStrings(expected, problem),
    }
}

test "an intact chain verifies and reports its head" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const chain = try testChain(allocator, &.{ "[\"event\",1]", "[\"event\",2]", "[\"event\",3]" });
    const check = try verifyChain(allocator, chain.public_key, chain.rows);
    try std.testing.expectEqual(@as(u64, 3), check.ok.?.seq);
    try std.testing.expectEqualStrings(chain.rows[2].hash, check.ok.?.hash);
    try std.testing.expectEqual(@as(?Head, null), (try verifyChain(allocator, chain.public_key, &.{})).ok);
}

test "an edited, missing or forged row breaks the chain" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const chain = try testChain(allocator, &.{ "[\"event\",1]", "[\"event\",2]", "[\"event\",3]" });

    var edited = try allocator.dupe(ChainRow, chain.rows);
    edited[1].preimage = "[\"event\",\"changed\"]";
    try expectProblem("row 2 does not match its hash", try verifyChain(allocator, chain.public_key, edited));

    const missing = [_]ChainRow{ chain.rows[0], chain.rows[2] };
    try expectProblem("row 2 is missing", try verifyChain(allocator, chain.public_key, &missing));

    // Whoever writes to the database can compute a hash, not a signature
    var forged = try allocator.dupe(ChainRow, chain.rows);
    forged[2].signature = chain.rows[1].signature;
    try expectProblem("row 3 has an invalid signature", try verifyChain(allocator, chain.public_key, forged));

    // Nor does another key verify
    const other = try testChain(allocator, &.{"x"});
    var other_key = try allocator.dupe(u8, other.public_key);
    other_key[0] = if (other_key[0] == 'A') 'B' else 'A';
    try std.testing.expect(try verifyChain(allocator, other_key, chain.rows) == .problem);
}

test "the witness catches a shortened or rewritten chain" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const chain = try testChain(allocator, &.{ "a", "b", "c" });
    const seen: Head = .{ .seq = 3, .hash = chain.rows[2].hash };

    try std.testing.expectEqual(@as(?[]const u8, null), try compareWithWitness(allocator, seen, chain.rows));
    try std.testing.expectEqual(@as(?[]const u8, null), try compareWithWitness(allocator, null, chain.rows));
    try std.testing.expectEqualStrings("has 2 rows, but had 3 when you last verified it", (try compareWithWitness(allocator, seen, chain.rows[0..2])).?);
    // Rebuilt from row 2 on and signed again: intact on its own, not against the witness
    const rewritten = try testChain(allocator, &.{ "a", "B", "c", "d" });
    try std.testing.expectEqualStrings("row 3 changed since you last verified it", (try compareWithWitness(allocator, seen, rewritten.rows)).?);
}
