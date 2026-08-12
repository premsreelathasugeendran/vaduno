import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // ONE real database backs every file in this package, and both test files
    // TRUNCATE shared tables as they go. Vitest's default is to run files in
    // parallel workers, which would let one file's TRUNCATE fire mid-test in
    // the other — a flake that reads as a store bug. Files run sequentially;
    // the concurrency each test needs is created deliberately inside it, with
    // two pools, never by accident of the runner.
    fileParallelism: false,
  },
});
