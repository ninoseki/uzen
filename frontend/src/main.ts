import "@fortawesome/fontawesome-free/css/all.css";
import "@fortawesome/fontawesome-free/js/all.js";
import "@mdi/font/css/materialdesignicons.css";
import "buefy/dist/buefy.css";

import VueCompositionAPI from "@vue/composition-api";
import Buefy from "buefy";
import Vue from "vue";

import App from "@/App.vue";
import router from "@/router";
import { truncate } from "@/utils/truncate";

Vue.use(Buefy);
Vue.use(VueCompositionAPI);

Vue.config.productionTip = false;

Vue.filter("truncate", truncate);

new Vue({
  router,
  render: (h) => h(App),
}).$mount("#app");
