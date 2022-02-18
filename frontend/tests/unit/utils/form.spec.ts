import { normalizeFilterValue } from "@/utils/form";

describe("Search form function", () => {
  describe("#normalizeFilterValue", () => {
    it("return a string of a data", () => {
      const date: Date = new Date("December 17, 1995 00:00:00 GMT");
      const str = normalizeFilterValue(date);
      expect(str).toEqual("1995-12-17T00:00:00.000Z");
    });

    it("return a value without any modification", () => {
      const str = normalizeFilterValue("foo");
      expect(str).toEqual("foo");

      const number = normalizeFilterValue(42);
      expect(number).toEqual(42);
    });
  });
});
