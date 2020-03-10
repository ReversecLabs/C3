<template>
  <div id="app">
    <Navbar />
    <div class="c3body" v-if="hasSelectedGateway === true">
      <div class="c3body-main">
        <GatewayForm />
        <Canvas />
        <Controll />
      </div>
      <SideMenu />
    </div>
    <div v-if="hasSelectedGateway === false" class="c3body-no-gateway-message">
      <h1>There are currently no active Gateways</h1>
      <p>
        Once a gateway has been detected it will automatically show up and this
        message will not appear, c3 checks for any gateway every minute.
      </p>
    </div>
    <CreateGatewayModal
      v-if="hasSelectedGateway === false"
      class="c3body-gateway"
    />
    <div></div>
    <Footer />
    <Modal />
    <Notification />
  </div>
</template>

<script lang="ts">
import Vue from 'vue';
import { Component, Watch } from 'vue-property-decorator';
import { State, Getter, Action, Mutation, namespace } from 'vuex-class';

import { Func } from '@/types/Func';
import { FetchC3DataFn } from './store/C3Module';
import { FetchC3CommandFn } from './store/C3Command';
import { gateway } from '../tests/unit/store/mockdata';
import { SetActualPageFn } from '@/store/PaginateModule';
import { GatewayHeader, C3Node, nullNode, NodeKlass } from '@/types/c3types';

import Modal from '@/components/Modal.vue';
import Canvas from '@/components/Canvas.vue';
import Footer from '@/components/Footer.vue';
import Navbar from '@/components/Navbar.vue';
import Controll from '@/components/Controll.vue';
import SideMenu from '@/components/SideMenu.vue';
import GatewayForm from '@/components/GatewayForm.vue';
import Notification from '@/components/Notification.vue';
import CreateGatewayModal from '@/components/modals/CreateGateway.vue';

const C3Module = namespace('c3Module');
const VisModule = namespace('visModule');
const PaginateModule = namespace('paginateModule');
const C3CommandModule = namespace('c3CommandModule');
const C3OptionsModule = namespace('optionsModule');

@Component({
  components: {
    Navbar,
    GatewayForm,
    Canvas,
    Controll,
    SideMenu,
    Footer,
    Modal,
    Notification,
    CreateGatewayModal
  }
})
export default class App extends Vue {
  @PaginateModule.Mutation public setActualPage!: SetActualPageFn;

  @C3Module.Action public fetchGateways!: Func;
  @C3Module.Action public fetchGateway!: FetchC3DataFn;
  @C3Module.Action public fetchCapability!: FetchC3DataFn;

  @C3Module.Getter public getGateway!: C3Node;
  @C3Module.Getter public getGateways!: GatewayHeader[];

  @VisModule.Action public generateNodes!: Func;

  @VisModule.Getter public getGrapData!: object;
  @VisModule.Getter public getAutoUpdateEnabled!: boolean;

  @C3CommandModule.Action public fetchCommands!: FetchC3CommandFn;

  @C3OptionsModule.Getter public getRefreshInterval!: number;

  public setTime: any;

  get gateway() {
    if (this.getGateway === undefined) {
      return nullNode;
    }

    return this.getGateway;
  }

  get hasSelectedGateway() {
    return this.getGateways.length > 0;
  }

  get refreshRate() {
    return this.getRefreshInterval;
  }

  public mounted(): void {
    this.updateData();

    this.setTime = setInterval(this.updateData, this.refreshRate);
  }

  public destroy(): void {
    clearInterval(this.setTime);
  }

  @Watch('getRefreshInterval')
  public setNewRefreshRate(value: any, oldValue: any) {
    clearInterval(this.setTime);
    this.setTime = setInterval(this.updateData, this.refreshRate);
  }

  @Watch('getGrapData')
  public onGetGrapDataChange(value: any, oldValue: any) {
    if ((window as any).networkc3 !== undefined) {
      (window as any).networkc3.setData(this.getGrapData);
    }
    this.fetchCommands(this.gateway.id);
    this.fetchCapability({ gatewayId: this.gateway.id });
  }

  public updateData(): void {
    if (this.getAutoUpdateEnabled === true) {
      this.fetchGateways();
      if (this.gateway && this.gateway.klass !== NodeKlass.Undefined) {
        this.fetchGateway({ gatewayId: this.gateway.id });
      }
    }
  }
}
</script>

<style lang="sass">
@import '~@/scss/colors.scss'
#app
    display: flex
    flex-direction: column
    height: 100vh
    width: 100vw
    overflow: hidden
    overflow-y: auto
    margin: 0
    padding: 0
.c3body
  display: flex
  flex-direction: row
  flex-grow: 1
  margin: 0 auto
  padding: 0
  width: 100%
  max-width: 1450px
  &-main
    display: flex
    flex-direction: column
    flex-grow: 1
    margin: 0
    padding: 16px 12px 16px 16px
  &-gateway
    max-width: 610px
    margin: 48px auto 0 auto
    height: auto
  &-no-gateway-message
    display: block
    background-color: $color-grey-900
    max-width: 610px
    margin: 48px auto 0 auto
    height: 120px
    padding: 1rem
    box-shadow: 0px 4px 4px rgba(0, 0, 0, 0.25)
    border-radius: 2px
    border-left: 8px solid $color-yellow-500
    h1
      margin: 0
      padding: 0
      font-family: "Roboto Mono"
      font-weight: 500
      font-size: 18px
      line-height: 25px
      letter-spacing: -0.05em
      color: $color-grey-400
    p
      margin: 0
      padding: 0 12px 0 0
      font-size: 14px
      line-height: 20px
      color: $color-grey-000
    h1+p
      margin-top: .5rem
</style>
