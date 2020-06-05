import { truncate } from "@/utils/truncate";

describe("truncate", () => {
  it("return truncated string", () => {
    expect(truncate("foo")).toEqual("foo");
    expect(truncate("foo", 2)).toEqual("fo...");
    expect(truncate("foo", 100)).toEqual("foo");
  });
});
