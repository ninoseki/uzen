import Vue from "vue";
import VueRouter from "vue-router";

import Home from "@/views/Home.vue";

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
    component: () =>
      import(/* webpackChunkName: "snapshots" */ "../views/Snapshots.vue"),
    meta: {
      title: "Snapshots - Uzen",
    },
  },
  {
    path: "/snapshots/:id",
    name: "Snapshot",
    component: () =>
      import(/* webpackChunkName: "snapshot" */ "../views/Snapshot.vue"),
    props: true,
  },
  {
    path: "/jobs/snapshots/:id",
    name: "SnapshotJob",
    component: () =>
      import(/* webpackChunkName: "snapshotJob" */ "../views/SnapshotJob.vue"),
    props: true,
  },
  {
    path: "/jobs/yara/:id",
    name: "YaraScanJob",
    component: () =>
      import(/* webpackChunkName: "yaraScanJob" */ "../views/YaraScanJob.vue"),
    props: true,
  },
  {
    path: "/jobs/similarity/:id",
    name: "SimilarityScanJob",
    component: () =>
      import(
        /* webpackChunkName: "similarityScanJob" */ "../views/SimilarityScanJob.vue"
      ),
    props: true,
  },
  {
    path: "/yara",
    name: "Yara",
    component: () => import(/* webpackChunkName: "yara" */ "../views/Yara.vue"),
    meta: {
      title: "YARA - Uzen",
    },
  },
  {
    path: "/similarity",
    name: "Similarity",
    component: () =>
      import(/* webpackChunkName: "similarity" */ "../views/Similarity.vue"),
    meta: {
      title: "Similarity - Uzen",
    },
  },
  {
    path: "/import",
    name: "Import",
    component: () =>
      import(/* webpackChunkName: "import" */ "../views/Import.vue"),
    meta: {
      title: "Import - Uzen",
    },
  },
  {
    path: "/rules",
    name: "Rules",
    component: () =>
      import(/* webpackChunkName: "rules" */ "../views/Rules.vue"),
    meta: {
      title: "Rules - Uzen",
    },
  },
  {
    path: "/rules/:id",
    name: "Rule",
    component: () => import(/* webpackChunkName: "rule" */ "../views/Rule.vue"),
  },
  {
    path: "/rules/edit/:id",
    name: "EditRule",
    component: () =>
      import(/* webpackChunkName: "editRule" */ "../views/EditRule.vue"),
    meta: {
      title: "Edit a rule - Uzen",
    },
  },
  {
    path: "/matches",
    name: "Matches",
    component: () =>
      import(/* webpackChunkName: "matches" */ "../views/Matches.vue"),
    meta: {
      title: "Matches - Uzen",
    },
  },
  {
    path: "/ip_address/:ipAddress",
    name: "IP address",
    component: () =>
      import(/* webpackChunkName: "ipAddress" */ "../views/IPAddress.vue"),
  },
  {
    path: "/domain/:hostname",
    name: "Domain",
    component: () =>
      import(/* webpackChunkName: "domain" */ "../views/Domain.vue"),
  },
  {
    path: "/file/:hash",
    name: "File",
    component: () => import(/* webpackChunkName: "file" */ "../views/File.vue"),
  },
  {
    path: "/bulk",
    name: "Bulk",
    component: () => import(/* webpackChunkName: "bulk" */ "../views/Bulk.vue"),
    meta: {
      title: "Bulk - Uzen",
    },
  },
  {
    path: "/configuration",
    name: "Configuration",
    component: () =>
      import(
        /* webpackChunkName: "configuration" */ "../views/Configuration.vue"
      ),
    meta: {
      title: "Configuration - Uzen",
    },
  },
];

const router = new VueRouter({
  routes,
});

router.beforeEach((to, _from, next) => {
  document.title = to.meta?.title || "";

  next();
});

export default router;
