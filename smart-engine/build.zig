const std = @import("std");

pub fn build(b: *std.Build) void {
    // Keep release artifacts portable across older VM CPU models.  Zig's
    // implicit target selection can otherwise inherit the build host's
    // SIMD features (for example AVX), which makes the C ABI fail with
    // SIGILL on a baseline x86_64 guest.  An explicit -Dcpu=native (or a
    // named CPU) still opts into that optimization when it is intentional.
    var target_query = b.standardTargetOptionsQueryOnly(.{});
    if (target_query.cpu_model == .determined_by_cpu_arch) {
        target_query.cpu_model = .baseline;
    }
    const target = b.resolveTargetQuery(target_query);
    const optimize = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "smart_engine",
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib.linkLibC();
    lib.addIncludePath(b.path("include"));
    b.installArtifact(lib);

    const tests = b.addTest(.{
        .root_source_file = b.path("src/lib.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run Smart policy core tests");
    test_step.dependOn(&run_tests.step);
}
