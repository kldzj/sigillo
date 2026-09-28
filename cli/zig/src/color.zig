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
    for (0..text.len) |i| {
        if (controlLen(text, i) > 0) break;
    } else return text;
    var out = try std.ArrayList(u8).initCapacity(allocator, text.len);
    var i: usize = 0;
    while (i < text.len) {
        const len = controlLen(text, i);
        out.appendAssumeCapacity(if (len > 0) '?' else text[i]);
        i += @max(len, 1);
    }
    return out.toOwnedSlice(allocator);
}

// The same, written straight to the terminal
pub fn writePlain(w: Writer, text: []const u8) !void {
    var i: usize = 0;
    while (i < text.len) {
        const len = controlLen(text, i);
        try w.writeByte(if (len > 0) '?' else text[i]);
        i += @max(len, 1);
    }
}

// How many bytes the control character at text[i] takes, 0 when there is
// none. UTF-8 writes the C1 controls as 0xC2 0x80..0x9F, and some terminals
// read 0xC2 0x9B like ESC [.
fn controlLen(text: []const u8, i: usize) usize {
    const c = text[i];
    if (c < 0x20 or c == 0x7f) return 1;
    if (c == 0xc2 and i + 1 < text.len and text[i + 1] >= 0x80 and text[i + 1] <= 0x9f) return 2;
    return 0;
}

test "plain turns control characters into question marks" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("website?]52;c;ZWNobyBoaQ==?", try plain(arena.allocator(), "website\x1b]52;c;ZWNobyBoaQ==\x07"));
    try std.testing.expectEqualStrings("Café / prod", try plain(arena.allocator(), "Café / prod"));
    try std.testing.expectEqualStrings("api?2K?1A?52;c;eA==?", try plain(arena.allocator(), "api\xc2\x9b2K\xc2\x9b1A\xc2\x9d52;c;eA==\xc2\x9c"));
    try std.testing.expectEqualStrings("no\xc2\xa0break", try plain(arena.allocator(), "no\xc2\xa0break"));
}
