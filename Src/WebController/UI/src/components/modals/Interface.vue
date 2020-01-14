<template>
  <div class="c3modal-body" v-if="c3Interface !== undefined">
    <div
      class="c3modal-header"
      :class="{
        'is-return': !!c3Interface.isReturnChannel,
        'has-error': !!c3Interface.error
      }"
    >
      <h1>
        <span class="capitalize">{{ c3Interface.klass.toLowerCase() }} </span>
        ID: {{ c3Interface.id || '' }}
      </h1>
      <div class="flex-row">
        <div class="details">
          <p>
            Parent
            <span class="c3link capitalize">
              {{ c3Interface.parentKlass.toLowerCase() }} /
              {{ c3Interface.parentId }}
            </span>
          </p>
          <p class="capitalize">
            {{ c3Interface.klass.toLowerCase() }} Type
            <span>
              {{ interfaceTypeName(c3Interface) }}
            </span>
          </p>
          <p>
            Jitter [min/max]
            <span>
              {{ getInterfaceJitter }}
            </span>
          </p>
        </div>

        <div class="actions">
          <span class="c3modal-more-btn icon more" v-if="showRelayDropdown">
            INTERFACE OPTIONS
          </span>
          <ul class="c3modal-menu">
            <li
              class="c3modal-menu-item"
              @click="
                openModal(c3Interface.id, 'CREATE_RELAY', generateOprions())
              "
              v-show="showNewRelayButton"
            >
              New Relay
            </li>
            <li
              class="c3modal-menu-item"
              @click="
                openModal(c3Interface.uid, 'CONNECT_RELAY', generateOprions())
              "
              v-show="showConnectRelayButton"
            >
              Connect Relay
            </li>
          </ul>
          <button
            class="c3btn c3btn--outline"
            v-on:click="openModal(c3Interface.uid, 'COMMAND_CENTER')"
          >
            Command Center
          </button>
        </div>
      </div>
      <p
        v-if="!!c3Interface.error && c3Interface.error !== ''"
        class="message-with-icon"
      >
        <span class="icon warning"></span>
        Error: {{ c3Interface.error }}
      </p>
      <p
        v-if="
          !!c3Interface.isReturnChannel &&
            c3Interface.isReturnChannel !== 'false'
        "
        class="message-with-icon"
      >
        <span class="icon return"></span>
        This is a Gateway Return Channel (GRC).
      </p>
      <p
        v-if="
          !!c3Interface.isNegotiationChannel &&
            c3Interface.isNegotiationChannel !== 'false'
        "
        class="message-with-icon"
      >
        <span class="icon exclamation"></span>
        This is a Negotiation Channel.
      </p>
    </div>
    <div class="c3modal-details">
      <template v-if="c3Interface.propertiesText !== ''">
        <h1>Properties</h1>
        <pre class="c3command">{{ c3Interface.propertiesText }}</pre>
      </template>
    </div>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Prop, Mixins } from 'vue-property-decorator';

import { Notify } from '@/store/NotifyModule';
import { GetInterfaceFn, GetNodeKlassFn, GetRelayFn } from '@/store/C3Module';
import {
  C3Interface,
  C3Gateway,
  C3Relay,
  NodeKlass,
  C3Node,
  C3FieldDefault,
  C3CommandCenterOptions,
  SourceOptions,
  nullNode
} from '@/types/c3types';

import C3 from '@/c3';

const nodeKlass = NodeKlass;
const C3Module = namespace('c3Module');

@Component
export default class InterfaceModal extends Mixins(C3) {
  @Prop() public targetId!: string;

  @C3Module.Getter public getRelay!: GetRelayFn;
  @C3Module.Getter public getInterface!: GetInterfaceFn;
  @C3Module.Getter public getNodeKlass!: GetNodeKlassFn;

  get c3Interface() {
    const target = this.getInterface(this.targetId);
    if (!target) {
      this.closeThisModal();
    }
    return target;
  }

  get showRelayDropdown() {
    return this.showConnectRelayButton || this.showNewRelayButton;
  }

  get showConnectRelayButton() {
    return this.showButtons();
  }

  get showNewRelayButton() {
    return this.showButtons();
  }

  public showButtons() {
    if (this.isReturnChannel() || !this.isChannel()) {
      return false;
    }
    return true;
  }

  get getInterfaceJitter() {
    if (this.c3Interface) {
      return this.c3Interface.propertiesText.jitter;
    }
    return '[N/A, N/A]';
  }

  public isChannel(): boolean {
    if (!!this.c3Interface) {
      return this.c3Interface.klass === NodeKlass.Channel;
    }
    return false;
  }

  public isReturnChannel(): boolean {
    if (!!this.c3Interface) {
      return this.c3Interface.isReturnChannel === true;
    }
    return false;
  }

  public isNegotiationChannel(): boolean {
    if (!!this.c3Interface) {
      return this.c3Interface.isNegotiationChannel === true;
    }
    return false;
  }

  public getArguments(node: C3Node = nullNode): any {
    if (this.isChannel()) {
      if (!!node.propertiesText && !!node.propertiesText.arguments) {
        return JSON.parse(JSON.stringify(node.propertiesText.arguments));
      }
    }
    return [];
  }

  public getArgumentsAttributes(interfaceAguments: any): any {
    if (Array.isArray(interfaceAguments[0])) {
      return interfaceAguments[0];
    }
    return [];
  }

  public getPropertiesArguments(interfaceAguments: any): C3FieldDefault[] {
    const propertiesAurguments: C3FieldDefault[] = [];

    Object.values(interfaceAguments).forEach(
      (objectOrArray: C3FieldDefault | any) => {
        if (!Array.isArray(objectOrArray)) {
          propertiesAurguments.push(objectOrArray);
        }
      }
    );

    return propertiesAurguments;
  }

  public getInterfaceParentId(): string {
    if (!!this.c3Interface && !!this.c3Interface.parentId) {
      return this.c3Interface.parentId;
    }
    return '';
  }

  public generateSourceOptions(): SourceOptions {
    return {
      relay: this.getRelay(this.getInterfaceParentId()),
      interface: this.c3Interface
    };
  }

  public changeInputOutputIDs(attributes: any) {
    let inputId = {
      name: '',
      type: '',
      value: ''
    };

    let outputId = {
      name: '',
      type: '',
      value: ''
    };

    let tmp = '';

    if (!!attributes.length) {
      inputId =
        attributes.find((a: C3FieldDefault) => {
          return a.name === 'Input ID';
        }) || '';
      outputId =
        attributes.find((a: C3FieldDefault) => {
          return a.name === 'Output ID';
        }) || '';
    }

    tmp = outputId.value;
    outputId.value = inputId.value;
    inputId.value = tmp;

    return attributes;
  }

  public isNormalChannel(): boolean {
    const argumentsString = JSON.stringify(this.getArguments(this.c3Interface));

    return (
      !!argumentsString.match(/Input ID/g) &&
      !!argumentsString.match(/Output ID/g)
    );
  }

  public generateCommandCenterArguments(): C3FieldDefault[] {
    const optionsArguments: C3FieldDefault[] = [];

    let attributes = this.getArgumentsAttributes(
      this.getArguments(this.c3Interface)
    );
    if (attributes.length > 0) {
      attributes = this.changeInputOutputIDs(attributes);
    }

    const propertiesArguments = this.getPropertiesArguments(
      this.getArguments(this.c3Interface)
    );

    if (!!attributes.length) {
      attributes.forEach((element: C3FieldDefault) => {
        optionsArguments.push(element);
      });
    }
    if (!!propertiesArguments.length) {
      propertiesArguments.forEach((element: C3FieldDefault) => {
        optionsArguments.push(element);
      });
    }

    return optionsArguments;
  }

  public getPrefix(): string {
    if (this.isNormalChannel()) {
      return 'AddChannel';
    }
    if (this.isNegotiationChannel()) {
      return 'AddNegotiationChannel';
    }
    return '';
  }

  public getInterfaceTypeString(): string {
    if (this.c3Interface) {
      return this.interfaceTypeName(this.c3Interface);
    }
    return '';
  }

  public generateOprions(): C3CommandCenterOptions {
    return {
      formDefault: {
        prefix: this.getPrefix(),
        interface: this.getInterfaceTypeString(),
        arguments: this.generateCommandCenterArguments()
      },
      source: this.generateSourceOptions()
    };
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
}
</script>

<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3modal
  &-more-btn
    position: relative
    cursor: pointer
    background-position-x: right !important
    align-self: flex-end
    margin-bottom: 8px
    width: auto
    padding-right: 24px
    line-height: 24px
    font-size: 12px
    color: $color-grey-000
  &-menu
    display: none
    flex-direction: column
    position: absolute
    right: 12px
    top: 64px
    flex-direction: column
    padding: 0
    background: $color-grey-800
    box-shadow: 0px 12px 24px rgba(0, 0, 0, 0.15)
    border-radius: 2px
    list-style: none
    min-width: 180px
    z-index: 9
    &-item
      display: flex
      align-items: center
      font-size: 14px
      line-height: 16px
      color: $color-grey-000
      height: 32px
      padding: 0 8px
      border-radius: 2px
      &:hover
        background-color: $color-grey-700
        cursor: pointer
    &-divider
      height: 0
      width: 100
      border-bottom: 1px solid $color-grey-800
    &:hover
      display: flex
  &-more-btn:hover + .c3modal-menu
    display: flex
</style>
