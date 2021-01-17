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
import "highlight.js/styles/androidstudio.css";

import { defineComponent } from "@vue/composition-api";

import Navbar from "@/components/ui/Navbar.vue";

export default defineComponent({
  name: "App",
  components: {
    Navbar,
  },
});
</script>

<style>
html {
  background-color: #f2f9ff !important;
}

.header {
  margin-bottom: 10px;
}

.header h2 {
  color: #5892d0;
}

pre {
  white-space: pre;
  white-space: pre-wrap;
  word-break: break-all;
  word-wrap: break-word;
}

.container .navbar {
  margin-bottom: 10px;
  border-bottom: 2px solid lightgray;
}
</style>
