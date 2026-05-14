import { describe, it, expect } from "vitest";
import { canEditTasks } from "@/lib/auth";

describe("canEditTasks", () => {
  it("returns true for admin", () => {
    expect(canEditTasks("admin")).toBe(true);
  });

  it("returns true for member", () => {
    expect(canEditTasks("member")).toBe(true);
  });

  it("returns false for viewer", () => {
    expect(canEditTasks("viewer")).toBe(false);
  });

  it("returns false for null/undefined role", () => {
    expect(canEditTasks(null)).toBe(false);
    expect(canEditTasks(undefined)).toBe(false);
  });
});