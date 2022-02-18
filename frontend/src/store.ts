import { createGlobalState, useLocalStorage } from "@vueuse/core";

export const useGlobalState = createGlobalState(() => {
  return useLocalStorage("uzen-vue-use-locale-storage", {
    apiKey: "",
  });
});
