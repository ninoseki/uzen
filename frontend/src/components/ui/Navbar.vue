<template>
  <b-navbar :fixed-top="true">
    <template slot="brand">
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
      <b-navbar-item tag="router-link" :to="{ path: '/yara' }"
        >YARA scan</b-navbar-item
      >
      <b-navbar-item tag="router-link" :to="{ path: '/oneshot' }"
        >Oneshot</b-navbar-item
      >
      <b-navbar-item tag="router-link" :to="{ path: '/import' }"
        >Import</b-navbar-item
      >
      <b-navbar-item>
        <a href="/docs" target="_blank" class="navbar-item">API</a>
      </b-navbar-item>
      <b-navbar-item>
        <a
          href="https://github.com/ninoseki/uzen"
          target="_blank"
          class="navbar-item"
          >GitHub</a
        >
      </b-navbar-item>
    </template>
  </b-navbar>
</template>

<script lang="ts">
import { Component, Vue } from "vue-property-decorator";

@Component
export default class Navbar extends Vue {}
</script>

<style>
.navbar {
  border-bottom: 1px solid #cce6ff;
}
</style>
