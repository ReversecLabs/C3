<template>
  <div class="c3modal-body">
    <div class="c3modal-details">
      <div class="c3modal-title-wrapper">
        <h1>Gateway Setup</h1>
        <span class="c3modal-config-link" v-on:click="openModal('', 'OPTIONS')">EDIT CONFIG</span>
      </div>
      <p>Please setup a Gateway to begin using c3.</p>
      <Input
        legend="Name / Auto Generated ID"
        class="form-element"
        @change="changeName($event, gatewayName)"
        help="If you do not enter a name an ID will be automatically generated."
      />
      <div class="form-row">
        <Select
          legend="TargetSuffix"
          class="form-element"
          :selected="selectedTargetSuffix"
          :options="{ exe: 'exe' }"
          :border="true"
          @change="changeTargetSuffix($event, targetSuffix)"
        />
        <Select
          legend="Architecture"
          class="form-element"
          :selected="selectedArchitecture"
          :options="{ x86: 'x86', x64: 'x64' }"
          :border="true"
          @change="changeArchitecture($event, architecture)"
        />
      </div>
      <dir class="flex-row c3modal-actions">
        <button
          class="c3btn c3btn--grey"
          v-on:click.self="closeThisModal()"
          v-show="hasSelectedGateway !== false"
        >
          Cancel
        </button>
        <button class="c3btn c3btn pull-right" v-on:click="createNewGateway()">
          Create and download Gateway
        </button>
      </dir>
    </div>
  </div>
</template>

<script lang="ts">
import axios from 'axios';
import { namespace } from 'vuex-class';
import { Component, Prop, Mixins } from 'vue-property-decorator';

import { GatewayHeader } from '@/types/c3types';

import C3 from '@/c3';
import Input from '@/components/form/Input.vue';
import Select from '@/components/form/Select.vue';

const C3Module = namespace('c3Module');
const C3OptionsModule = namespace('optionsModule');

@Component({
  components: {
    Input,
    Select
  }
})
export default class CreateGatewayModal extends Mixins(C3) {
  @Prop() public targetId!: string;

  @C3Module.Getter public getGateways!: GatewayHeader[];

  @C3OptionsModule.Getter public getAPIBaseUrl!: string;

  public gatewayName: string = '';
  public targetSuffix: string = 'exe';
  public architecture: string = 'x64';

  get selectedTargetSuffix() {
    return this.targetSuffix;
  }

  get selectedArchitecture() {
    return this.architecture;
  }

  get hasSelectedGateway() {
    return this.getGateways.length > 0;
  }

  public mounted(): void {
    (window as any).addEventListener('keydown', this.handleGlobalKeyDown, true);
  }

  public beforeDestroy(): void {
    (window as any).removeEventListener(
      'keydown',
      this.handleGlobalKeyDown,
      true
    );
  }

  public changeName(n: any): void {
    this.gatewayName = n.value;
  }

  public changeTargetSuffix(t: string): void {
    this.targetSuffix = t;
  }

  public changeArchitecture(a: string): void {
    this.architecture = a;
  }

  public createNewGateway(): void {
    let apiUrl = `/api/gateway/exe/${this.architecture}`;
    if (this.gatewayName && this.gatewayName !== '') {
      apiUrl = apiUrl + `?name=${this.gatewayName}`;
    }
    axios({
      url: apiUrl,
      method: 'GET',
      baseURL: this.getAPIBaseUrl,
      responseType: 'blob'
    })
      .then(response => {
        const blob = new Blob([response.data], { type: response.data.type });
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        const contentDisposition = response.headers['content-disposition'];
        let fileName = '';

        if (contentDisposition !== undefined) {
          fileName = contentDisposition
            .split('filename=')[1]
            .split(';')[0]
            .replace(/%20/gi, '-');
        }

        if (typeof fileName !== 'string' || fileName === '') {
          fileName = 'gateway.exe';
        }

        link.href = url;
        link.setAttribute('download', fileName);
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.URL.revokeObjectURL(url);

        this.closeThisModal();
      })
      .catch(error => {
        this.addNotify({
          type: 'error',
          message: error.message
        });
        // tslint:disable-next-line:no-console
        console.error(error.message);
      });
  }
}
</script>
