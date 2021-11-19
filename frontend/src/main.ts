import "@fortawesome/fontawesome-free/css/all.css";
import "@fortawesome/fontawesome-free/js/all.js";
import "@mdi/font/css/materialdesignicons.css";
import "bulma/css/bulma.css";
import "bulma-helpers/css/bulma-helpers.min.css";
import "highlight.js/styles/androidstudio.css";
import "vue3-date-time-picker/dist/main.css";

import { createApp } from "vue";

import App from "./App.vue";
import router from "./router";

createApp(App).use(router).mount("#app");
