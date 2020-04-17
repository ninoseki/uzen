import { SearchFormMixin } from "@/components/mixins";

describe("SearchFormMixin", () => {
  const subject = new SearchFormMixin();

  describe("#dateFormatter", () => {
    it("return a string of a data", () => {
      const date: Date = new Date("December 17, 1995");
      const str = subject.dateFormatter(date);
      expect(str).toEqual("1995-12-16");
    });
  });

  describe("#normalizeFilterValue", () => {
    it("return a string of a data", () => {
      const date: Date = new Date("December 17, 1995");
      const str = subject.normalizeFilterValue(date);
      expect(str).toEqual("1995-12-16");
    });

    it("return a value without any modification", () => {
      const str = subject.normalizeFilterValue("foo");
      expect(str).toEqual("foo");

      const number = subject.normalizeFilterValue(42);
      expect(number).toEqual(42);
    });
  });
});
