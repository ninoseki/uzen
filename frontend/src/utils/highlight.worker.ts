import { useWebWorkerFn } from "@vueuse/core";

function highlight(html: string): string {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const result = (self as any).hljs.highlightAuto(html);
  return result.value;
}

const { workerFn } = useWebWorkerFn(highlight, {
  dependencies: [
    "https://cdnjs.cloudflare.com/ajax/libs/highlight.js/10.5.0/highlight.min.js",
  ],
});

export const highlightWorkerFn = workerFn;
