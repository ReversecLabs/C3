<template>
  <div class="c3modal-body">
    <div class="c3modal-header">
      <h1>Source Relay &amp; Interface</h1>
      <div class="flex-row">
        <div class="details">
          <p>
            Relay <span>&nbsp;{{ relay.name }} / {{ relay.id }}</span>
          </p>
          <p>
            Build ID <span>{{ relay.buildId }}</span>
          </p>
          <p>
            {{ c3Interface.klass.toLowerCase() }} ID
            <span>{{ c3Interface.id || '' }}</span>
          </p>
          <p>
            {{ c3Interface.klass.toLowerCase() }} Type
            <span>{{ interfaceTypeName(c3Interface) }}</span>
          </p>
        </div>
      </div>
    </div>
    <div class="c3modal-details">
      <div style="padding-bottom:24px;">
        <h1>Select target Relay</h1>
        <Select
          legend="Target Relay"
          class="form-element"
          :selected="selectedRelay"
          :options="generateRelayList()"
          :border="true"
          @change="changeTargetRelay($event, targetRelay)"
        />
      </div>

      <div class="c3modal-form">
        <CommandCenterModal
          class="embeded-modal"
          :target-id="selectedRelay"
          :embeded="false"
          @change="changeForm($event, formData)"
          :options="addNewRelayGroupToOptions"
        />
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Mixins, Prop } from 'vue-property-decorator';

import {
  C3Gateway,
  NodeKlass,
  C3Node,
  C3Relay,
  nullNode
} from '@/types/c3types';
import {
  GetTypesForInterfaceKlassFn,
  InterfaceItem,
  GetCommandTargetForFn
} from '@/store/C3Capability';

import C3 from '@/c3';
import Input from '@/components/form/Input.vue';
import Select from '@/components/form/Select.vue';
import GeneralForm from '@/components/form/GeneralForm.vue';
import AddChannelForm from '@/components/form/AddChannelForm.vue';
import CommandCenterModal from './CommandCenter.vue';
import {
  GetRelayFn,
  GetInterfaceFn,
  GetInterfacesForFn
} from '@/store/C3Module';

const C3Module = namespace('c3Module');
const C3Capability = namespace('c3Capability');

@Component({
  components: {
    Input,
    Select,
    GeneralForm,
    CommandCenterModal
  }
})
export default class ConnectRelayModal extends Mixins(C3) {
  @Prop() public targetId!: string;
  @Prop() public options!: any;

  @C3Capability.Getter public getCommandTargetFor!: GetCommandTargetForFn;
  @C3Capability.Getter
  public getTypesForInterfaceKlass!: GetTypesForInterfaceKlassFn;

  @C3Module.Getter public getRelays!: C3Node[];
  @C3Module.Getter public getRelay!: GetRelayFn;
  @C3Module.Getter public getInterface!: GetInterfaceFn;
  @C3Module.Getter public getInterfacesFor!: GetInterfacesForFn;

  public formData: any = {};
  public isValid: boolean = false;
  public targetRelay: string = '';

  get relay() {
    return this.sourceRelay;
  }

  get c3Interface() {
    return this.sourceInterface;
  }

  get hasOptions() {
    if (this.options) {
      return JSON.stringify(this.options) === '{}' ? false : true;
    }
    return false;
  }

  get sourceRelay() {
    if (this.hasOptions) {
      if (!!this.options.source && !!this.options.source.relay) {
        return this.options.source.relay;
      }
    }
    return nullNode;
  }

  get sourceInterface() {
    if (this.hasOptions) {
      if (!!this.options.source && !!this.options.source.interface) {
        return this.options.source.interface;
      }
    }
    return nullNode;
  }

  // check the form is valid
  get formIsValid() {
    return !this.isValid;
  }

  // hold the actual selected relay
  get selectedRelay() {
    return this.targetRelay;
  }

  get addNewRelayGroupToOptions() {
    return {
      formDefault: this.options.formDefault,
      source: this.options.source,
      targetGroup: 'NewRelayCommandGroup'
    };
  }

  public generateRelayList(): any {
    const selectOptions: any = {};
    let first: string = '';
    let optionsCount = 0;
    const nullLiteral: string = 'null';
    const nodes = this.getRelays;
    nodes.forEach((node, index) => {
      if (node.id !== this.relay.id) {
        optionsCount++;
        selectOptions[node.id] = `${node.id} ${
          node.name ? '- ' + node.name + ' ' : ''
        }`;
        if (first === '') {
          first = node.id;
        }
      }
    });
    if (optionsCount === 0) {
      selectOptions[nullLiteral] = `Nothing to select...`;
      first = nullLiteral;
    }
    // select the first relay if nothing selected yet
    if (this.targetRelay === '') {
      this.targetRelay = first;
    }
    return selectOptions;
  }

  get showConnectRelayButton() {
    return true;
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

  public changeForm(data: any): void {
    this.isValid = data.valid;
    this.formData = data.data;
  }

  public changeTargetRelay(t: string): void {
    this.targetRelay = t;
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
