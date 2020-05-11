import Vue from "vue";
import App from "./App.vue";
import router from "./router";

import "@fortawesome/fontawesome-free/css/all.css";
import "@fortawesome/fontawesome-free/js/all.js";
import "@mdi/font/css/materialdesignicons.css";
import "highlight.js/styles/github.css";

import Buefy from "buefy";
import "buefy/dist/buefy.css";

Vue.use(Buefy);

Vue.config.productionTip = false;

new Vue({
  router,
  render: (h) => h(App),
}).$mount("#app");
