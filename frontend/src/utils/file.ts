import { useAsyncTask } from "vue-concurrency";
import { Task } from "vue-concurrency/dist/vue2/src/Task";

import { API } from "@/api";
import { File } from "@/types";

export function generateGetFileTask(): Task<File, [string]> {
  return useAsyncTask<File, [string]>(async (_, sha256: string) => {
    return await API.getFile(sha256);
  });
}
