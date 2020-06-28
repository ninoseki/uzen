<template>
  <div>
    <b-message type="is-info">
      Number of scripts: {{ this.scripts.length }}
    </b-message>
    <b-field>
      <b-select
        placeholder="Select a script"
        expanded
        v-model="selectedID"
        @input="showSelectedScript"
      >
        <option v-for="script in scripts" :value="script.id" :key="script.id">
          {{ script.url }}
        </option>
      </b-select>
    </b-field>
    <ScriptView v-if="hasSelectedScript" v-bind:script="selectedScript" />
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from "vue-property-decorator";

import ScriptView from "@/components/scripts/Script.vue";
import { Script } from "@/types";

@Component({
  components: {
    ScriptView,
  },
})
export default class ScriptsView extends Vue {
  @Prop() private scripts!: Script[];
  private selectedID: string | null = null;
  private selectedScript: Script | undefined = undefined;

  showSelectedScript() {
    const script = this.scripts.find((elem) => elem.id === this.selectedID);
    this.selectedScript = script;
  }

  get hasSelectedScript(): boolean {
    return this.selectedScript !== undefined;
  }
}
</script>
