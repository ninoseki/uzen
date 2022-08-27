<template>
  <nav class="navbar" role="navigation" aria-label="main navigation">
    <div class="navbar-brand">
      <div class="navbar-item">
        <img src="/images/logo.png" alt="Uzen" />
      </div>

      <div class="navbar-item">
        <h1 class="title">Uzen</h1>
      </div>
    </div>

    <div class="navbar-menu">
      <div class="navbar-end">
        <router-link class="navbar-item" :to="{ path: '/' }">Home</router-link>
        <router-link class="navbar-item" :to="{ path: '/snapshots' }"
          >Snapshots</router-link
        >
        <router-link class="navbar-item" :to="{ path: '/rules/new' }"
          >New rule</router-link
        >
        <router-link class="navbar-item" :to="{ path: '/rules' }"
          >Rules</router-link
        >
        <router-link class="navbar-item" :to="{ path: '/matches' }"
          >Matches</router-link
        >
        <router-link class="navbar-item" :to="{ path: '/yara' }"
          >YARA</router-link
        >
        <router-link class="navbar-item" :to="{ path: '/similarity' }"
          >Similarity</router-link
        >
        <router-link class="navbar-item" :to="{ path: '/bulk' }"
          >Bulk submission</router-link
        >
        <router-link class="navbar-item" :to="{ path: '/configuration' }"
          >Configuration</router-link
        >
        <a href="/docs" target="_blank" class="navbar-item">API</a>
      </div>
    </div>
  </nav>
</template>

<script lang="ts">
import { defineComponent } from "vue";

export default defineComponent({
  name: "NavBar",
});
</script>

<style>
.navbar {
  border-bottom: 1px solid #cce6ff;
}
</style>
