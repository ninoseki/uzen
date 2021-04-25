import Vue from "vue";
import VueRouter from "vue-router";

import Bulk from "@/views/Bulk.vue";
import Configuration from "@/views/Configuration.vue";
import Domain from "@/views/Domain.vue";
import EditRule from "@/views/EditRule.vue";
import Home from "@/views/Home.vue";
import Import from "@/views/Import.vue";
import IPAddress from "@/views/IPAddress.vue";
import Matches from "@/views/Matches.vue";
import Rule from "@/views/Rule.vue";
import Rules from "@/views/Rules.vue";
import Snapshot from "@/views/Snapshot.vue";
import SnapshotJob from "@/views/SnapshotJob.vue";
import Snapshots from "@/views/Snapshots.vue";
import Yara from "@/views/Yara.vue";
import YaraScanJob from "@/views/YaraScanJob.vue";

Vue.use(VueRouter);

const routes = [
  {
    path: "/",
    name: "Home",
    component: Home,
    meta: {
      title: "Uzen",
    },
  },
  {
    path: "/snapshots",
    name: "Snapshots",
    component: Snapshots,
    meta: {
      title: "Snapshots - Uzen",
    },
  },
  {
    path: "/snapshots/:id",
    name: "Snapshot",
    component: Snapshot,
    props: true,
  },
  {
    path: "/jobs/snapshots/:id",
    name: "SnapshotJob",
    component: SnapshotJob,
    props: true,
  },
  {
    path: "/jobs/yara/:id",
    name: "YaraScanJob",
    component: YaraScanJob,
    props: true,
  },
  {
    path: "/yara",
    name: "Yara",
    component: Yara,
    meta: {
      title: "YARA - Uzen",
    },
  },
  {
    path: "/import",
    name: "Import",
    component: Import,
    meta: {
      title: "Import - Uzen",
    },
  },
  {
    path: "/rules",
    name: "Rules",
    component: Rules,
    meta: {
      title: "Rules - Uzen",
    },
  },
  {
    path: "/rules/:id",
    name: "Rule",
    component: Rule,
  },
  {
    path: "/rules/edit/:id",
    name: "EditRule",
    component: EditRule,
    meta: {
      title: "Edit a rule - Uzen",
    },
  },
  {
    path: "/matches",
    name: "Matches",
    component: Matches,
    meta: {
      title: "Matches - Uzen",
    },
  },
  {
    path: "/ip_address/:ipAddress",
    name: "IP address",
    component: IPAddress,
  },
  {
    path: "/domain/:hostname",
    name: "Domain",
    component: Domain,
  },
  {
    path: "/bulk",
    name: "Bulk",
    component: Bulk,
    meta: {
      title: "Bulk - Uzen",
    },
  },
  {
    path: "/configuration",
    name: "Configuration",
    component: Configuration,
    meta: {
      title: "Configuration - Uzen",
    },
  },
];

const router = new VueRouter({
  routes,
});

router.beforeEach((to, _from, next) => {
  document.title = to.meta.title || "";

  next();
});

export default router;
