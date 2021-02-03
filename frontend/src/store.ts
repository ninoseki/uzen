import { createGlobalState, useLocalStorage } from "@vueuse/core";

export const useGlobalState = createGlobalState(() => {
  return useLocalStorage("vue-use-locale-storage", {
    apiKey: "",
  });
});
