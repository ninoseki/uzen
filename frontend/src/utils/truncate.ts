export function truncate(text: string, length = 64, clamp = "..."): string {
  if (text.length <= length) {
    return text;
  }
  const truncated = text.slice(0, length - clamp.length);
  return truncated + clamp;
}
