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
import "highlight.js/styles/default.css";

import { Component, Vue } from "vue-property-decorator";

import Navbar from "@/components/ui/Navbar.vue";

@Component({
  components: {
    Navbar,
  },
})
export default class App extends Vue {}
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

h2.middle {
  padding-bottom: 10px;
  margin-bottom: 10px;
  border-bottom: 2px solid lightgray;
}

pre {
  word-break: normal;
}
pre code.hljs {
  background-color: whitesmoke;
  color: #4a4a4a;
}

.container .navbar {
  margin-bottom: 10px;
  border-bottom: 2px solid lightgray;
}
</style>
