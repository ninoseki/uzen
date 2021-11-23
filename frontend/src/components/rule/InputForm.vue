<template>
  <div id="form">
    <div class="field">
      <label class="label">Name</label>
      <div class="control">
        <input
          class="input"
          type="text"
          placeholder="Name of a YARA rule"
          v-model="name_"
        />
      </div>
    </div>

    <div class="field">
      <label class="label">Target</label>
      <div class="control">
        <div class="select">
          <select placeholder="Target for a YARA rule" v-model="target_">
            <option v-for="t in targets" :value="t" :key="t">{{ t }}</option>

            <option>Select dropdown</option>
            <option>With options</option>
          </select>
        </div>
      </div>
    </div>

    <div class="field">
      <label class="label">YARA rule</label>
      <div class="control">
        <textarea
          class="textarea is-expanded"
          type="textarea"
          rows="10"
          placeholder="rule foo: bar {strings: $a = 'lmn' condition: $a}"
          v-model="source_"
        />
      </div>
    </div>

    <div class="field">
      <label class="label">Allowed network addresses</label>
      <div class="control">
        <input
          class="input"
          type="text"
          placeholder="1.1.1.1,example.com,AS100"
          v-model="allowedNetworkAddresses_"
        />
      </div>
      <p class="help">IP addresses, domains, ASNs to be allowed (Optional)</p>
    </div>

    <div class="field">
      <label class="label">Disallowed network addresses</label>
      <div class="control">
        <input
          class="input"
          type="text"
          placeholder="1.1.1.1,example.com,AS100"
          v-model="disallowedNetworkAddresses_"
        />
      </div>
      <p class="help">
        IP addresses, domains, ASNs not to be allowed (Optional)
      </p>
    </div>

    <div class="field">
      <label class="label">Allowed resource hashes</label>
      <div class="control">
        <input
          class="input"
          type="text"
          placeholder="ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9,..."
          v-model="allowedResourceHashes_"
        />
      </div>
      <p class="help">
        SHA256 hashes of scripts, stylesheets to be allowed (Optional)
      </p>
    </div>

    <div class="field">
      <label class="label">Disallowed resource hashes</label>
      <div class="control">
        <input
          class="input"
          type="text"
          placeholder="ea8fac7c65fb589b0d53560f5251f74f9e9b243478dcb6b3ea79b5e36449c8d9,..."
          v-model="disallowedResourceHashes_"
        />
      </div>
      <p class="help">
        SHA256 hashes of scripts, stylesheets not to be allowed (Optional)
      </p>
    </div>
  </div>
</template>

<script lang="ts">
import { defineComponent, ref } from "vue";

import { TargetTypes } from "@/types";
import { CreateRulePayload } from "@/types/rule";

export default defineComponent({
  name: "RuleInputForm",
  props: {
    name: {
      type: String,
      required: true,
    },
    target: {
      type: String,
      required: true,
    },
    source: {
      type: String,
      required: true,
    },
    allowedNetworkAddresses: {
      type: String,
    },
    disallowedNetworkAddresses: {
      type: String,
    },
    allowedResourceHashes: {
      type: String,
    },
    disallowedResourceHashes: {
      type: String,
    },
  },
  setup(props) {
    const targets: TargetTypes[] = ["html", "whois", "certificate", "script"];
    const name_ = ref(props.name);
    const target_ = ref(props.target);
    const source_ = ref(props.source);

    const allowedNetworkAddresses_ = ref(props.allowedNetworkAddresses);
    const disallowedNetworkAddresses_ = ref(props.disallowedNetworkAddresses);
    const allowedResourceHashes_ = ref(props.allowedResourceHashes);
    const disallowedResourceHashes_ = ref(props.disallowedResourceHashes);

    const normalizeUndefinableString = (
      v: string | undefined
    ): string | undefined => {
      if (v === undefined) {
        return undefined;
      }

      if (v === "") {
        return undefined;
      }
      return v;
    };

    const getPayload = (): CreateRulePayload => {
      return {
        name: name_.value,
        target: target_.value,
        source: source_.value,
        allowedNetworkAddresses: normalizeUndefinableString(
          allowedNetworkAddresses_.value
        ),
        disallowedNetworkAddresses: normalizeUndefinableString(
          disallowedNetworkAddresses_.value
        ),
        allowedResourceHashes: normalizeUndefinableString(
          allowedResourceHashes_.value
        ),
        disallowedResourceHashes: normalizeUndefinableString(
          disallowedResourceHashes_.value
        ),
      };
    };

    return {
      targets,
      name_,
      source_,
      target_,
      allowedNetworkAddresses_,
      disallowedNetworkAddresses_,
      allowedResourceHashes_,
      disallowedResourceHashes_,
      getPayload,
    };
  },
});
</script>
