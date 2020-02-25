import Vue from "vue";
import VueRouter from "vue-router";

import Home from "@/views/Home.vue";
import Snapshots from "@/views/Snapshots.vue";
import Yara from "@/views/Yara.vue";
import Import from "@/views/Import.vue";

Vue.use(VueRouter);

const routes = [
  {
    path: "/",
    name: "Home",
    component: Home
  },
  {
    path: "/snapshots",
    name: "Snapshots",
    component: Snapshots
  },
  {
    path: "/yara",
    name: "Yara",
    component: Yara
  },
  {
    path: "/import",
    name: "Import",
    component: Import
  }
];

const router = new VueRouter({
  routes
});

export default router;
