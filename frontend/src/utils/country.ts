import { countryCodeEmoji } from "country-code-emoji";

export function countryCodeToEmoji(countryCode: string | null): string {
  if (countryCode === null) {
    return "";
  }

  return countryCodeEmoji(countryCode);
}
