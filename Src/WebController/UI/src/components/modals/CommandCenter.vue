<template>
  <div class="c3modal-body">
    <div class="c3modal-details">
      <h1 v-if="isNotEmbeded">
        Create Command for: {{ currentItem.klass }} - {{ currentItem.name }}
        {{ interfaceTypeName(currentItem) }}/ {{ currentItem.id }}
      </h1>
      <div class="c3command-group">
        <Select
          legend="Select Command Group"
          class="form-element"
          :selected="selectedCommandGroup"
          :options="commandGroupOptions"
          :border="true"
          @change="changeCommandGroup($event, commandGroup)"
          v-show="false"
        />
        <Select
          legend="Select Command"
          class="form-element"
          :selected="selectedCommandTarget"
          :options="commandTargetOptions"
          :border="true"
          @change="changeCommandTarget($event, commandTarget)"
        />
      </div>
      <GeneralForm
        :key="selectedInterface + selectedCommand + selectedCommand"
        v-if="selectedInterface !== undefined && selectedCommand !== undefined"
        :klass="selectedInterfaceKlass"
        :interface-name="selectedInterface"
        :command="selectedCommand"
        @change="changeForm($event, formData)"
        :target-id="targetId"
        :target="selectedInterface"
        :options="argumentOptions"
      />
      <dir class="flex-row c3modal-actions" v-if="isNotEmbeded">
        <button class="c3btn c3btn--grey" v-on:click.self="closeThisModal()">
          Cancel
        </button>
        <button
          class="c3btn"
          v-on:click="sendCommand()"
          :disabled="formIsValid"
        >
          Send Command
        </button>
      </dir>
    </div>
  </div>
</template>

<script lang="ts">
import pluralize from 'pluralize';
import axios from 'axios';
import { namespace } from 'vuex-class';
import { Component, Prop, Mixins } from 'vue-property-decorator';

import { GetInterfaceFn } from '@/store/C3Module';
import { C3Gateway, NodeKlass, C3CommandCenterOptions } from '@/types/c3types';
import {
  GetTypesForInterfaceKlassFn,
  GetCommandGroupForFn,
  GetCommandTargetForFn,
  GetCapabilityForFn
} from '@/store/C3Capability';

import C3 from '@/c3';
import Input from '@/components/form/Input.vue';
import Select from '@/components/form/Select.vue';
import GeneralForm from '@/components/form/GeneralForm.vue';
import AddChannelForm from '@/components/form/AddChannelForm.vue';

const C3Module = namespace('c3Module');
const C3Capability = namespace('c3Capability');
const C3OptionsModule = namespace('optionsModule');

@Component({
  components: {
    Input,
    Select,
    GeneralForm
  }
})
export default class CommandCenterModal extends Mixins(C3) {
  @Prop() public targetId!: string;
  @Prop() public embeded!: boolean;
  @Prop() public options!: C3CommandCenterOptions;

  @C3Module.Getter public getInterface!: GetInterfaceFn;

  @C3Capability.Getter public getCapabilityFor!: GetCapabilityForFn;
  @C3Capability.Getter public getCommandGroupFor!: GetCommandGroupForFn;
  @C3Capability.Getter public getCommandTargetFor!: GetCommandTargetForFn;

  @C3OptionsModule.Getter public getAPIBaseUrl!: string;

  public formData: any = {};
  public isValid: boolean = false;
  public commandGroup: string = '';
  public commandTarget: string = '';
  public formDirty: boolean = false;

  get formIsValid() {
    return !this.isValid;
  }

  get currentItem() {
    return this.getInterface(this.targetId);
  }

  get selectedCommandGroup() {
    if (!this.commandGroup) {
      return this.defaultCommandGroup;
    }
    this.resetForm();
    return this.commandGroup;
  }

  get selectedCommandTarget() {
    if (!this.commandTarget) {
      return this.defaultCommandTarget;
    }
    return this.commandTarget;
  }

  get defaultCommandGroup() {
    if (this.options !== undefined && this.options.targetGroup !== undefined) {
      return this.options.targetGroup;
    }
    if (!!this.commandGroupOptions) {
      return Object.keys(this.commandGroupOptions)[0];
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

  get commandGroupOptions() {
    if (!!this.currentItem) {
      return this.getCommandGroupFor(this.currentItem.klass);
    }
    return '';
  }

  get commandTargetOptions() {
    if (!!this.currentItem) {
      if (
        this.currentItem.klass === NodeKlass.Gateway ||
        this.currentItem.klass === NodeKlass.Relay
      ) {
        return this.getCommandTargetFor(
          this.selectedCommandGroup,
          this.currentItem.klass
        );
      }
      return this.getCommandTargetFor(
        this.selectedCommandGroup,
        this.currentItem.klass,
        this.interfaceTypeName(this.currentItem)
      );
    }
    return '';
  }

  get selectedInterfaceKlass() {
    if (this.commandTarget !== undefined) {
      return pluralize.singular(this.commandTarget.split('_')[0]).toUpperCase();
    }
    return '';
  }

  get selectedInterface() {
    if (this.commandTarget !== undefined) {
      return this.commandTarget.split('_')[1];
    }
    return '';
  }

  get selectedCommand() {
    if (this.commandTarget !== undefined) {
      return this.commandTarget.split('_')[2];
    }
    return '';
  }

  get getCommandId() {
    const capability = this.getCapabilityFor(
      this.selectedInterface,
      this.selectedInterfaceKlass as NodeKlass
    );
    if (!!capability) {
      const com = capability.commands.find((c: any) => {
        return c.name === this.selectedCommand;
      });
      return com.id;
    }
    return '';
  }

  get isNotEmbeded(): boolean {
    if (this.embeded === undefined) {
      return true;
    }
    return this.embeded === true ? false : true;
  }

  get hasOptions() {
    if (this.options) {
      return JSON.stringify(this.options) === '{}' ? false : true;
    }
    return false;
  }

  get argumentOptions() {
    if (this.hasOptions) {
      if (!!this.options.formDefault) {
        return this.options.formDefault.arguments;
      }
    }
    return false;
  }

  public mounted(): void {
    (window as any).addEventListener('keydown', this.handleGlobalKeyDown, true);
    if (this.hasOptions) {
      if (!!this.options.formDefault) {
        const target = Object.keys(this.commandTargetOptions).find(key => {
          if (!!this.options && !!this.options.formDefault) {
            // TODO: found a better way to found the must select options.
            return (
              this.commandTargetOptions[key] ===
              this.options.formDefault.prefix +
                this.options.formDefault.interface
            );
          }
          return false;
        });
        if (!!target) {
          this.commandTarget = target;
        }
      }
    }
  }

  public beforeDestroy(): void {
    (window as any).removeEventListener(
      'keydown',
      this.handleGlobalKeyDown,
      true
    );
  }

  public resetForm(): void {
    this.commandTarget = '';
  }

  public changeForm(data: any): void {
    this.isValid = data.valid;
    if (data.data.length === 1 && data.data[0].length === 0) {
      this.formData = [];
    } else {
      if (data.data[0].length === 0) {
        data.data.shift();
      }
      this.formData = data.data;
    }

    // if the command center embeded to the new relay form we
    // want to give the form data to create relay form
    if (this.targetId === 'new') {
      const dataToEmit = {
        name: this.selectedCommandGroup,
        data: {
          id: this.getCommandId,
          name: this.selectedInterface,
          command: this.selectedCommand,
          arguments: this.formData
        }
      };
      this.$emit('change', {
        data: dataToEmit,
        valid: this.isValid
      });
    }
  }

  public changeCommandGroup(n: string): void {
    this.commandGroup = n;
  }

  public changeCommandTarget(n: string): void {
    this.isValid = true;
    this.commandTarget = n;
  }

  public sendCommand(): void {
    const data = {
      name: this.selectedCommandGroup,
      data: {
        id: this.getCommandId,
        name: this.selectedInterface,
        command: this.selectedCommand,
        arguments: this.formData
      }
    };

    // POST /api/gateway/{gatewayId}/command
    // POST /api/gateway/{gatewayId}/interface/{interfaceId}/command
    // POST /api/gateway/{gatewayId}/relay/{relayId}/command
    // POST /api/gateway/{gatewayId}/relay/{relayId}/interface/{interfaceId}/command

    let apiURL = '/api/gateway/';

    if (!!this.currentItem && this.currentItem.klass === NodeKlass.Gateway) {
      apiURL = apiURL + `${this.currentItem.id}/command`;
    }
    if (!!this.currentItem && this.currentItem.klass === NodeKlass.Relay) {
      apiURL =
        apiURL +
        `${this.currentItem.parentId}/relay/${this.currentItem.id}/command`;
    }
    if (
      (!!this.currentItem && this.currentItem.klass === NodeKlass.Channel) ||
      (!!this.currentItem && this.currentItem.klass === NodeKlass.Peripheral) ||
      (!!this.currentItem && this.currentItem.klass === NodeKlass.Connector)
    ) {
      if (this.currentItem.parentKlass === NodeKlass.Gateway) {
        switch (this.currentItem.klass) {
          case NodeKlass.Channel:
            apiURL =
              apiURL +
              `${this.currentItem.parentId}/channel/${this.currentItem.id}/command`;
            break;
          case NodeKlass.Peripheral:
            apiURL =
              apiURL +
              `${this.currentItem.parentId}/peripheral/${this.currentItem.id}/command`;
            break;
          case NodeKlass.Connector:
            apiURL =
              apiURL +
              `${this.currentItem.parentId}/connector/${this.currentItem.id}/command`;
            break;
        }
      }
      if (this.currentItem.parentKlass === NodeKlass.Relay) {
        switch (this.currentItem.klass) {
          case NodeKlass.Channel:
            apiURL =
              apiURL +
              `${this.gateway.id}/relay/${this.currentItem.parentId}/channel/${this.currentItem.id}/command`;
            break;
          case NodeKlass.Peripheral:
            apiURL =
              apiURL +
              `${this.gateway.id}/relay/${this.currentItem.parentId}/peripheral/${this.currentItem.id}/command`;
            break;
          case NodeKlass.Connector:
            apiURL =
              apiURL +
              `${this.gateway.id}/relay/${this.currentItem.parentId}/connector/${this.currentItem.id}/command`;
            break;
        }
      }
    }
    axios({
      url: apiURL,
      method: 'POST',
      baseURL: this.getAPIBaseUrl,
      data
    })
      .then(response => {
        this.addNotify({
          type: 'info',
          message: 'Command successfully sent...'
        });
        this.closeThisModal();
      })
      .catch(error => {
        const msg: string = 'Command NOT sent: ' + error.message;
        this.addNotify({
          type: 'error',
          message: msg
        });
        // tslint:disable-next-line:no-console
        console.error(error.message);
      });
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style lang="sass">
@import '~@/scss/colors.scss'
.c3command
  &-group
    margin: 16px 0
</style>
