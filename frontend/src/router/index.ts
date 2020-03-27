import Vue from "vue";
import VueRouter from "vue-router";

import Home from "@/views/Home.vue";
import Import from "@/views/Import.vue";
import Oneshot from "@/views/Oneshot.vue";
import Snapshot from "@/views/Snapshot.vue";
import Snapshots from "@/views/Snapshots.vue";
import Yara from "@/views/Yara.vue";

Vue.use(VueRouter);

const routes = [
  {
    path: "/",
    name: "Home",
    component: Home,
  },
  {
    path: "/snapshots",
    name: "Snapshots",
    component: Snapshots,
  },
  {
    path: "/yara",
    name: "Yara",
    component: Yara,
  },
  {
    path: "/import",
    name: "Import",
    component: Import,
  },
  {
    path: "/oneshot",
    name: "Oneshot",
    component: Oneshot,
  },
  {
    path: "/snapshots/:id",
    name: "Snapshot",
    component: Snapshot,
    props: true,
  },
];

const router = new VueRouter({
  routes,
});

export default router;
