import "@testing-library/jest-dom/vitest";

// jsdom does not implement the object-URL APIs. The download helper only
// needs them to exist so tests can spy on them; provide inert stubs.
if (typeof URL.createObjectURL !== "function") {
  URL.createObjectURL = () => "blob:stub";
}
if (typeof URL.revokeObjectURL !== "function") {
  URL.revokeObjectURL = () => undefined;
}
