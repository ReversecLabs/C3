<template>
  <div class="c3modal-body">
    <div class="c3modal-details">
      <h1>Relay Setup</h1>
      <p>Please setup a Relay.</p>
      <Input
        legend="Name / Auto Generated ID"
        class="form-element"
        @change="changeName($event, relayName)"
        help="If you do not enter a name an ID will be automatically generated."
      />
      <Input
        legend="Parent Gateway Build ID"
        class="form-element"
        :value="gatewayBuildsId"
        :disabled="true"
      />
      <div class="form-row">
        <Select
          legend="TargetSuffix"
          class="form-element"
          :selected="selectedTargetSuffix"
          :options="{ dll: 'dll', exe: 'exe', shellcode: 'shellcode' }"
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
      <div class="c3modal-form">
        <DonutForm
          v-if="donutSelected"
          @change="changeDonutForm($event, formData)"
        />
      </div>
      <div class="c3modal-form">
        <h1>Add Command</h1>
        <p>Please Select the first command to the Relay.</p>
        <CommandCenterModal
          class="embeded-modal"
          :target-id="'new'"
          :embeded="true"
          @change="changeForm($event, formData)"
          :options="addNewRelayToOptions"
        />
      </div>
      <dir class="flex-row c3modal-actions">
        <button class="c3btn c3btn--grey" v-on:click.self="closeThisModal()">
          Cancel
        </button>
        <button
          class="c3btn c3btn"
          v-on:click="createNewRelay()"
          :disabled="formIsValid"
        >
          Create and Download Relay
        </button>
      </dir>
    </div>
  </div>
</template>

<script lang="ts">
import axios from 'axios';
import { namespace } from 'vuex-class';
import { Component, Mixins, Prop } from 'vue-property-decorator';

import { C3Gateway, NodeKlass, C3CommandCenterOptions } from '@/types/c3types';
import {
  GetTypesForInterfaceKlassFn,
  InterfaceItem,
  GetCommandTargetForFn
} from '@/store/C3Capability';

import C3 from '@/c3';
import Input from '@/components/form/Input.vue';
import Select from '@/components/form/Select.vue';
import DonutForm from '@/components/partial/DonutForm.vue';
import GeneralForm from '@/components/form/GeneralForm.vue';
import AddChannelForm from '@/components/form/AddChannelForm.vue';
import CommandCenterModal from './CommandCenter.vue';

const C3Module = namespace('c3Module');
const C3Capability = namespace('c3Capability');
const C3OptionsModule = namespace('optionsModule');

@Component({
  components: {
    Input,
    Select,
    DonutForm,
    GeneralForm,
    CommandCenterModal
  }
})
export default class CreateRelayModal extends Mixins(C3) {
  @Prop() public options!: C3CommandCenterOptions;

  @C3Capability.Getter public getCommandTargetFor!: GetCommandTargetForFn;
  @C3Capability.Getter
  public getTypesForInterfaceKlass!: GetTypesForInterfaceKlassFn;

  @C3OptionsModule.Getter public getAPIBaseUrl!: string;

  public formData: any = {};
  public relayName: string = '';
  public isValid: boolean = false;
  public targetSuffix: string = 'exe';
  public architecture: string = 'x64';
  public commandGroup: string = 'Relay';
  public commandTarget: string = '';
  public donutSelected: boolean = false;
  public donutFormData: object = {};

  get formIsValid() {
    return !this.isValid;
  }

  get selectedTargetSuffix() {
    return this.targetSuffix;
  }

  get selectedArchitecture() {
    return this.architecture;
  }

  get gatewayBuildsId() {
    if (this.gateway.buildId) {
      return this.gateway.buildId;
    }
    return '';
  }

  get selectedCommand() {
    if (this.commandTarget !== undefined) {
      return this.commandTarget.split('_')[2];
    }
    return '';
  }

  get selectedCommandTarget() {
    if (!this.commandTarget) {
      return this.defaultCommandTarget;
    }
    return this.commandTarget;
  }

  get commandTargetOptions() {
    return this.getCommandTargetFor('NewRelayCommandGroup', NodeKlass.Relay);
  }

  get selectedCommandGroup() {
    if (!this.commandGroup) {
      return this.commandGroup;
    }
    return '';
  }

  get selectedInterface() {
    if (this.commandTarget !== undefined) {
      return this.commandTarget.split('_')[1];
    }
    return '';
  }

  get defaultCommandTarget() {
    if (!!this.commandTargetOptions) {
      this.changeCommandTarget(Object.keys(this.commandTargetOptions)[0]);
      return Object.keys(this.commandTargetOptions)[0];
    }
    return '';
  }

  get addNewRelayToOptions() {
    return {
      formDefault: this.options.formDefault,
      source: this.options.source,
      targetGroup: 'NewRelayCommandGroup'
    };
  }

  public changeCommandTarget(n: string): void {
    this.isValid = true;
    this.commandTarget = n;
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
    this.relayName = n.value;
  }

  public changeForm(data: any): void {
    this.isValid = data.valid;
    this.formData = data.data;
  }

  public changeDonutForm(data: any): void {
    this.donutFormData = data;
  }

  public changeTargetSuffix(t: string): void {
    this.targetSuffix = t;
    this.donutSelected =
      this.targetSuffix === 'shellcode'
        ? (this.donutSelected = true)
        : (this.donutSelected = false);
  }

  public changeArchitecture(a: string): void {
    this.architecture = a;
  }

  public createNewRelay(): void {
    const data = {
      type: this.selectedTargetSuffix,
      architecture: this.selectedArchitecture,
      parentGatewayBuildId: this.gatewayBuildsId,
      name: this.relayName,
      startupCommands: [this.formData],
      donut: this.donutFormData
    };
    axios({
      url: '/api/build/customize',
      method: 'POST',
      baseURL: this.getAPIBaseUrl,
      data,
      responseType: 'blob'
    })
      .then(response => {
        let fileName = '';
        const blob = new Blob([response.data], { type: response.data.type });
        const contentDisposition = response.headers['content-disposition'];
        const url = window.URL.createObjectURL(blob);
        const link = document.createElement('a');

        link.href = url;

        if (contentDisposition !== undefined) {
          fileName = contentDisposition
            .split('filename=')[1]
            .split(';')[0]
            .replace(/%20/gi, '-');
        }

        if (typeof fileName !== 'string' || fileName === '') {
          fileName = 'relay.exe';
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

<style lang="sass">
@import '~@/scss/colors.scss'
.embeded-modal
  margin-bottom: 16px
  .c3modal-details
    box-shadow: none
    padding: 0
</style>
