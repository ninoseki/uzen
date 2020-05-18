import Vue from "vue";
import VueRouter from "vue-router";

import Home from "@/views/Home.vue";
import IPAddress from "@/views/IPAddress.vue";
import Import from "@/views/Import.vue";
import Matches from "@/views/Matches.vue";
import Oneshot from "@/views/Oneshot.vue";
import Rule from "@/views/Rule.vue";
import Rules from "@/views/Rules.vue";
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
    path: "/snapshots/:id",
    name: "Snapshot",
    component: Snapshot,
    props: true,
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
    path: "/rules",
    name: "Rules",
    component: Rules,
  },
  {
    path: "/rules/:id",
    name: "Rule",
    component: Rule,
  },
  {
    path: "/matches",
    name: "Matches",
    component: Matches,
  },
  {
    path: "/ip_address/:ipAddress",
    name: "IP address",
    component: IPAddress,
  },
];

const router = new VueRouter({
  routes,
});

export default router;
