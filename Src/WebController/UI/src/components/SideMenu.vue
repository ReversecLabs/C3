<template>
  <div class="c3side">
    <div class="c3side-title-wrapper">
      <h1 class="c3side-title">Network</h1>
      <span class="c3side-config-link" v-on:click="openModal('', 'OPTIONS')"
        >EDIT CONFIG</span
      >
    </div>
    <div class="c3side-body">
      <NetworkStats />

      <div class="c3side-refresh-wrapper">
        <span class="c3side-refres-title">
          Refresh Rate
        </span>
        <Select
          class="c3site-refresh-dropdown"
          style="margin-bottom: 0;"
          :selected="selectedRefreshRate"
          :options="refreshRates()"
          :border="false"
          @change="setRefreshRate($event, refreshRate)"
        />
      </div>

      <Toggle
        key="toggle-auto-update-button"
        legend="Auto Update"
        @change="toggleAutoUpdate($event)"
        name="autoUpdate"
        :checked="getAutoUpdateEnabled"
        help="Auto Update checks for network changes automatically,
          this may result in live updated to the graph and data tables when enabled"
        :disabled="false"
      />

      <div class="c3btn-group">
        <button
          class="c3btn c3btn--grey"
          v-on:click="openModal('', 'CREATE_GATEWAY')"
        >
          New Gateway
        </button>
        <!-- <button class="c3btn c3btn--grey" v-on:click="openModal('', 'CREATE_RELAY')">New Relay</button> -->
      </div>
    </div>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Mixins } from 'vue-property-decorator';

import { GetInterfacesFn } from '@/store/C3Module';
import { SetAutoUpdateEnabledFn } from '@/store/VisModule';
import { GatewayHeader, NodeKlass, C3Node } from '@/types/c3types';

import C3 from '@/c3';
import Toggle from '@/components/form/Toggle.vue';
import NetworkStats from '@/components/partial/NetworkStats.vue';
import Select from '@/components/form/Select.vue';
import { SetRefreshIntervalFn } from '@/store/OptionsModule';

const C3Module = namespace('c3Module');
const VisModule = namespace('visModule');
const C3OptionsModule = namespace('optionsModule');

@Component({
  components: {
    Toggle,
    Select,
    NetworkStats
  }
})
export default class SideMenu extends Mixins(C3) {
  @VisModule.Getter public getAutoUpdateEnabled!: boolean;
  @VisModule.Mutation public setAutoUpdateEnabled!: SetAutoUpdateEnabledFn;

  @C3OptionsModule.Getter public getRefreshInterval!: number;
  @C3OptionsModule.Mutation public setRefreshInterval!: SetRefreshIntervalFn;

  public refreshRate: string = '2';

  get getAutoUpdate() {
    return this.getAutoUpdateEnabled;
  }

  public toggleAutoUpdate(d: any): void {
    this.setAutoUpdateEnabled(d.value);
  }

  get selectedRefreshRate() {
    return this.refreshRate;
  }

  public setRefreshRate(rate: any) {
    this.refreshRate = rate;
    this.setRefreshInterval(parseInt(rate, 10) * 1000);
  }

  private refreshRates() {
    return {
      1: '1 second',
      2: '2 seconds',
      5: '5 seconds',
      10: '10 seconds',
      20: '20 seconds',
      30: '30 seconds',
      60: '1 minute',
      120: '2 minutes',
      300: '5 minutes',
      600: '10 minutes',
      1800: '30 minutes',
      3600: '1 hour'
    };
  }
}
</script>

<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3side
  display: flex
  flex-direction: column
  flex-grow: 1
  margin: 0 auto
  margin-top: 150px
  padding: 16px 16px 16px 12px
  width: 100%
  max-width: 250px
  &-title-wrapper
    border-bottom: 2px solid #E0E0E0
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
    display: flexc3btn-group
    align-self: flex-end
    text-align: right
    padding-bottom: 2px
    cursor: pointer
  &-body
    display: flex
    flex-direction: column
    padding: 8px
  &-refresh-wrapper
    display: flex
    flex-direction: row
    justify-content: space-between
    margin-top: -24px
  &-refres-title
    line-height: 32px
    flex-grow: 1
  &-refres-dropdown
    margin-bottom: 0
    flex-grow: 0
  .c3btn-group
    margin-top: 24px
</style>
