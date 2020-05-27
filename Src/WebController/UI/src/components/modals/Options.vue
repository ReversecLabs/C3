<template>
  <div class="c3modal-body">
    <div class="c3modal-details">
      <h1 class="c3network-title">
        Network Configuration
      </h1>
      <div class="form-row ">
        <Input
          legend="Url"
          class="form-element"
          :value="c3Url"
          :disabled="false"
          @change="setUrl($event, c3Url)"
          validate="required"
          name="Url"
          :key="'c3-url-field'"
        />
      </div>
      <div class="form-row">
        <Input
          legend="Port"
          class="form-element"
          :value="c3Port"
          :disabled="false"
          @change="setPort($event, c3Port)"
          validate="required|numeric|max_value:65535"
          name="Port"
          :key="'c3-port-field'"
        />
      </div>
      <dir class="flex-row c3modal-actions">
        <button class="c3btn c3btn--grey" v-on:click.self="closeThisModal()">
          Cancel
        </button>
        <button
          class="c3btn c3btn pull-right"
          v-on:click="saveNetworkConfig()"
          :disabled="!isFormValid"
        >
          Save Confing
        </button>
      </dir>
    </div>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Mixins } from 'vue-property-decorator';

import C3 from '@/c3';
import { SetBaseURLFn, SetBasePortFn } from '@/store/OptionsModule';
import Input from '../form/Input.vue';

const C3OptionsModule = namespace('optionsModule');

@Component({
  components: {
    Input
  }
})
export default class OptionsModal extends Mixins(C3) {
  @C3OptionsModule.Getter public getAPIUrl!: string;
  @C3OptionsModule.Getter public getAPIPort!: string;
  @C3OptionsModule.Mutation public setBaseURL!: SetBaseURLFn;
  @C3OptionsModule.Mutation public setBasePort!: SetBasePortFn;

  public c3Url: string = 'http://localhost';
  public c3UrlIsValid: boolean = true;
  public c3Port: number = 52935;
  public c3PortIsValid: boolean = true;

  get getUrl() {
    return this.getAPIUrl;
  }

  get getPort() {
    return this.getAPIPort;
  }

  public setUrl(url: any) {
    if (url.valid) {
      this.c3UrlIsValid = true;
      this.c3Url = url.value;
    } else {
      this.c3UrlIsValid = false;
    }
  }

  public setPort(port: any) {
    if (port.valid) {
      this.c3PortIsValid = true;
      this.c3Port = parseInt(port.value, 10);
    } else {
      this.c3PortIsValid = false;
    }
  }

  get isFormValid() {
    return this.c3UrlIsValid && this.c3PortIsValid;
  }

  public saveNetworkConfig(): void {
    if (this.isFormValid) {
      this.setBaseURL(this.c3Url);
      this.setBasePort(this.c3Port);
    }
  }

  public created() {
    this.c3Url = this.getUrl;
    this.c3Port = parseInt(this.getPort, 10);
  }
}
</script>
