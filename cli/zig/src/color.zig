// ANSI color helpers for terminal output.
// Each function wraps text in escape codes, only emitting them when
// the file descriptor is a TTY (so piped/redirected output stays clean).

const std = @import("std");

const File = std.fs.File;
pub const Writer = File.DeprecatedWriter;

pub const reset = "\x1b[0m";
pub const bold_s = "\x1b[1m";
pub const dim_s = "\x1b[2m";
pub const red_s = "\x1b[31m";
pub const green_s = "\x1b[32m";
pub const blue_s = "\x1b[34m";
pub const yellow_s = "\x1b[33m";
pub const cyan_s = "\x1b[36m";

pub fn isTty(writer: Writer) bool {
    const handle = writer.context.handle;
    return std.posix.isatty(handle);
}

pub fn bold(w: Writer, text: []const u8) !void {
    if (isTty(w)) {
        try w.writeAll(bold_s);
        try w.writeAll(text);
        try w.writeAll(reset);
    } else try w.writeAll(text);
}

pub fn green(w: Writer, text: []const u8) !void {
    if (isTty(w)) {
        try w.writeAll(green_s);
        try w.writeAll(text);
        try w.writeAll(reset);
    } else try w.writeAll(text);
}

pub fn blue(w: Writer, text: []const u8) !void {
    if (isTty(w)) {
        try w.writeAll(blue_s);
        try w.writeAll(text);
        try w.writeAll(reset);
    } else try w.writeAll(text);
}

pub fn cyan(w: Writer, text: []const u8) !void {
    if (isTty(w)) {
        try w.writeAll(cyan_s);
        try w.writeAll(text);
        try w.writeAll(reset);
    } else try w.writeAll(text);
}

pub fn dim(w: Writer, text: []const u8) !void {
    if (isTty(w)) {
        try w.writeAll(dim_s);
        try w.writeAll(text);
        try w.writeAll(reset);
    } else try w.writeAll(text);
}

pub fn yellow(w: Writer, text: []const u8) !void {
    if (isTty(w)) {
        try w.writeAll(yellow_s);
        try w.writeAll(text);
        try w.writeAll(reset);
    } else try w.writeAll(text);
}

pub fn err(w: Writer, text: []const u8) !void {
    if (isTty(w)) {
        try w.writeAll(bold_s);
        try w.writeAll(red_s);
        try w.writeAll(text);
        try w.writeAll(reset);
    } else try w.writeAll(text);
}

// Text from the server, for the terminal. A name anyone in the org can set
// could otherwise hold escape sequences that rewrite lines, set the clipboard
// or hide a link: control characters print as '?'.
pub fn plain(allocator: std.mem.Allocator, text: []const u8) ![]const u8 {
    for (text) |c| {
        if (c < 0x20 or c == 0x7f) break;
    } else return text;
    const out = try allocator.dupe(u8, text);
    for (out) |*c| {
        if (c.* < 0x20 or c.* == 0x7f) c.* = '?';
    }
    return out;
}

// The same, written straight to the terminal
pub fn writePlain(w: Writer, text: []const u8) !void {
    for (text) |c| try w.writeByte(if (c < 0x20 or c == 0x7f) '?' else c);
}

test "plain turns control characters into question marks" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("website?]52;c;ZWNobyBoaQ==?", try plain(arena.allocator(), "website\x1b]52;c;ZWNobyBoaQ==\x07"));
    try std.testing.expectEqualStrings("Café / prod", try plain(arena.allocator(), "Café / prod"));
}
