<template>
  <div id="app">
    <Navbar />
    <section class="section is-medium">
      <div class="container">
        <router-view />
      </div>
    </section>
  </div>
</template>

<script lang="ts">
import { Vue, Component } from "vue-property-decorator";

import Navbar from "@/components/Navbar.vue";

@Component({
  components: {
    Navbar
  }
})
export default class App extends Vue {}
</script>

<style>
html {
  background-color: #f2f9ff !important;
}
</style>