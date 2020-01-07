<template>
  <div class="c3modal" :class="this.activeModal.modalTarget.toLowerCase()" v-if="currentModal">
    <div class="c3modal-holder">
      <GatewayModal v-if="isGateway()" :target-id="targetUid" />
      <RelayModal v-if="isRelay()" :target-id="targetUid" />
      <CreateGatewayModal v-if="this.activeModal.modalTarget === 'CREATE_GATEWAY'" />
      <CreateRelayModal
        v-if="this.activeModal.modalTarget === 'CREATE_RELAY'"
        :options="options()"
      />
      <CommandCenterModal
        v-if="this.activeModal.modalTarget === 'COMMAND_CENTER'"
        :target-id="targetUid"
        :options="options()"
      />
      <ConnectRelayModal
        v-if="this.activeModal.modalTarget === 'CONNECT_RELAY'"
        :target-id="targetUid"
        :options="options()"
      />
      <CommandModal v-if="this.activeModal.modalTarget === 'COMMAND'" :target-id="targetUid" />
      <OptionsModal v-if="this.activeModal.modalTarget === 'OPTIONS'" />
      <InterfaceModal v-if="isInterface()" :target-id="targetUid" />
      <span class="c3modal-back icon back" v-on:click.self="closeThisModal()">Back</span>
      <span class="c3modal-close icon close" v-on:click.self="closeAllModal()"></span>
    </div>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Mixins } from 'vue-property-decorator';

import { NodeKlass } from '@/types/c3types';
import { C3Modal } from '@/store/ModalModule';

import C3 from '@/c3';
import RelayModal from '@/components/modals/Relay.vue';
import CommandModal from '@/components/modals/Command.vue';
import GatewayModal from '@/components/modals/Gateway.vue';
import InterfaceModal from '@/components/modals/Interface.vue';
import CreateRelayModal from '@/components/modals/CreateRelay.vue';
import CommandCenterModal from '@/components/modals/CommandCenter.vue';
import CreateGatewayModal from '@/components/modals/CreateGateway.vue';
import ConnectRelayModal from '@/components/modals/ConnectRelays.vue';
import OptionsModal from '@/components/modals/Options.vue';

const ModalModule = namespace('modalModule');

@Component({
  components: {
    RelayModal,
    CommandModal,
    GatewayModal,
    OptionsModal,
    InterfaceModal,
    CreateRelayModal,
    ConnectRelayModal,
    CommandCenterModal,
    CreateGatewayModal,
  },
})
export default class Modal extends Mixins(C3) {
  @ModalModule.Getter public activeModal!: C3Modal;

  get currentModal() {
    return this.activeModal;
  }

  get targetUid() {
    return this.activeModal.modalTargetId || '';
  }

  public isGateway(): boolean {
    return this.activeModal.modalTarget === NodeKlass.Gateway;
  }

  public isRelay(): boolean {
    return this.activeModal.modalTarget === NodeKlass.Relay;
  }

  public isChannel(): boolean {
    return this.activeModal.modalTarget === NodeKlass.Channel;
  }

  public isPeripheral(): boolean {
    return this.activeModal.modalTarget === NodeKlass.Peripheral;
  }

  public isConnector(): boolean {
    return this.activeModal.modalTarget === NodeKlass.Connector;
  }

  public isInterface(): boolean {
    return (
      this.activeModal.modalTarget === NodeKlass.Channel ||
      this.activeModal.modalTarget === NodeKlass.Peripheral ||
      this.activeModal.modalTarget === NodeKlass.Connector
    );
  }

  public options(): any {
    return this.activeModal.modalOptions;
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style lang="sass">
@import '~@/scss/colors.scss'
.c3modal
  display: block
  position: fixed
  background-color: rgba(0, 0, 0, .5)
  width: 100vw
  height: 100vh
  margin: 0
  padding: 0
  top: 0
  left: 0
  z-index: 11
  .actions
    flex-grow: 1
    justify-content: flex-end
    align-self: self-start
    align-items: self-end
    display: flex
    flex-direction: column
    .c3btn
      align-self: flex-end
  &-holder
    position: relative
    display: block
    margin: 15vh auto
    width: 900px
    max-width: calc(100vw - 3rem)
    max-height: 70vh
    overflow: hidden
    overflow-y: auto
    background: $color-grey-c3

  &-body
    display: block
    margin: 0
    padding: 0
    width: 100%
    height: 100%
    position: relative
    background-color: $color-grey-c3
    h1
      font-family: "Roboto Mono"
      font-weight: 500
      font-size: 18px
      line-height: 25px
      display: flex
      align-items: center
      letter-spacing: -0.05em
      color: $color-grey-400
      margin: 0 0 8px
      height: 32px
      .details
        min-width: 300px
        p
          font-size: 14px
          line-height: 20px
          padding: 0
          margin: 0 0 8px 0
          color: $color-grey-000
          display: flex
          justify-content: space-between
          &:last-of-type
            margin-bottom: 16px
  &-close
    position: absolute
    top: 22px
    right: 12px
    cursor: pointer
    background-color: transparent
  span.c3modal-back.c3modal-back
    display: flex
    position: absolute
    top: 22px
    right: 52px
    cursor: pointer
    text-transform: uppercase
    font-size: 12px
    line-height: 17px
    align-items: center
    padding-left: 24px
    background-position-x: left
    width: auto
    background-color: transparent
    &:hover
      background-position-x: left
  &-header
    background: $color-grey-900
    border-radius: 2px 2px 2px 0px
    padding: 16px
    margin-bottom:8px
    &.is-return
      background: linear-gradient(to bottom, $color-purple-500 4px, $color-grey-900 4px)
    &.has-error
      background: linear-gradient(to bottom, $color-red-500 4px, $color-grey-900 4px)
    .message-with-icon
      display: flex
      justify-content: left
      align-items: center
      span
        margin-right: 8px
  &-details
    padding-top: 24px
    box-shadow: 0px 1px 2px rgba(0, 0, 0, 0.5)
    border-radius: 2px
    padding: 16px
    padding-bottom: 24px
    table:not(:last-of-type)
      margin-bottom: 2rem
  &-body
    .form-row
      display: flex
      flex-direction: row
      justify-content: space-between
      .form-element:not(:last-of-type)
        margin-right: 8px
      .form-element:not(:first-of-type)
        margin-left: 8px
  &-actions.c3modal-actions
    display: flex
    justify-content: flex-end
    padding: 0
    margin: 24px 0 0 0
    .c3btn
      margin-left: 16px
  &.options
    .c3modal-back.c3modal-back
      display: none
    h1
      margin-bottom: 16px
  &-title-wrapper
    // border-bottom: 2px solid #E0E0E0
    display: flex
    justify-content: space-between
  &-title
    font-family: "Roboto Mono"
    font-weight: 500
    font-size: 18px
    line-height: 25px
    align-items: center
    letter-spacing: -0.05em
    margin: 0
    color: $color-grey-400
  &-config-link
    font-family: "Roboto"
    color: $color-blue-c3
    font-size: 12px
    line-height: 120%
    display: flex
    align-self: flex-end
    text-align: right
    margin: 0 0 14px
    cursor: pointer
</style>
