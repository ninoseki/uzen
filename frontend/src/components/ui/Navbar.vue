<template>
  <b-navbar>
    <template slot="brand">
      <b-navbar-item>
        <img src="/images/logo.png" alt="Uzen" />
      </b-navbar-item>
      <b-navbar-item>
        <h1 class="title">Uzen</h1>
      </b-navbar-item>
    </template>
    <template slot="end">
      <b-navbar-item tag="router-link" :to="{ path: '/' }">Home</b-navbar-item>
      <b-navbar-item tag="router-link" :to="{ path: '/snapshots' }"
        >Snapshots</b-navbar-item
      >
      <b-navbar-item tag="router-link" :to="{ path: '/rules' }"
        >Rules</b-navbar-item
      >
      <b-navbar-item tag="router-link" :to="{ path: '/matches' }"
        >Matches</b-navbar-item
      >
      <b-navbar-item tag="router-link" :to="{ path: '/yara' }"
        >YARA</b-navbar-item
      >
      <b-navbar-item tag="router-link" :to="{ path: '/similarity' }"
        >Similarity</b-navbar-item
      >
      <b-navbar-item tag="router-link" :to="{ path: '/import' }"
        >Import</b-navbar-item
      >
      <b-navbar-item tag="router-link" :to="{ path: '/bulk' }"
        >Bulk submission</b-navbar-item
      >
      <b-navbar-item tag="router-link" :to="{ path: '/configuration' }"
        >Configuration</b-navbar-item
      >
      <b-navbar-item>
        <a href="/docs" target="_blank" class="navbar-item">API</a>
      </b-navbar-item>
    </template>
  </b-navbar>
</template>

<script lang="ts">
import { defineComponent } from "@vue/composition-api";

export default defineComponent({
  name: "NavBar",
});
</script>

<style>
.navbar {
  border-bottom: 1px solid #cce6ff;
}
</style>
