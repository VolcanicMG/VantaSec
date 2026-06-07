import { defineConfig } from "vitest/config";
import { fileURLToPath } from "node:url";

/**
 * Vitest configuration.
 *
 * Single responsibility: run the unit suite for the pure scanner-logic modules
 * (guard, services, target) in a Node environment. Network checkers are not
 * unit-tested here — they touch live sockets and belong in integration tests.
 */
export default defineConfig({
  resolve: {
    // Mirror the Next.js "@/*" -> "src/*" alias so tests import the same way.
    alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) },
  },
  test: {
    environment: "node",
    include: ["tests/**/*.test.js"],
  },
});
