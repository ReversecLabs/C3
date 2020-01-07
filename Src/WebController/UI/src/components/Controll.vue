<template>
  <div class="c3controll" v-if="hasSelectedGateway">
    <span class="c3controll-help icon exclamation"></span>
    <ul class="c3controll-tabs">
      <li :class="{ active: activeIsRelay }" v-on:click="setActiveTab('relay')">Relays</li>
      <li :class="{ active: activeIsInterface }" v-on:click="setActiveTab('interface')">Interfaces</li>
      <li :class="{ active: activeIsCommands }" v-on:click="setActiveTab('command')">Commands</li>
    </ul>
    <RelaysTab v-if="activeIsRelay"/>
    <InterfacesTab v-if="activeIsInterface"/>
    <CommandsTab v-if="activeIsCommands"/>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Mixins } from 'vue-property-decorator';

import { SetActualPageFn } from '@/store/PaginateModule';

import C3 from '@/c3';
import RelaysTab from '@/components/datatables/Relays.vue';
import CommandsTab from '@/components/datatables/Commands.vue';
import InterfacesTab from '@/components/datatables/Interfaces.vue';

const C3Module = namespace('c3Module');
const PaginateModule = namespace('paginateModule');

@Component({
  components: {
    RelaysTab,
    CommandsTab,
    InterfacesTab,
  },
})
export default class Controll extends Mixins(C3) {
  @PaginateModule.Mutation public setActualPage!: SetActualPageFn;

  @C3Module.Getter public hasGatewaySelected!: boolean;

  public activeTab: string = 'relay';

  get activeIsRelay() {
    return this.activeTab === 'relay';
  }

  get activeIsInterface() {
    return this.activeTab === 'interface';
  }

  get activeIsCommands() {
    return this.activeTab === 'command';
  }

  get hasSelectedGateway() {
    return this.hasGatewaySelected;
  }

  public setActiveTab(s: string): void {
    this.setActualPage(1);
    this.activeTab = s;
  }
}
</script>

<style lang="sass">
@import '~@/scss/colors.scss'
.c3controll
  display: flex
  flex-direction: column
  flex-grow: 1
  flex-shrink: 1
  margin: 30px auto 30px auto
  padding: 24px
  background: $color-grey-c3
  box-shadow: 0px 1px 2px rgba(0, 0, 0, 0.5)
  border-radius: 2px
  width: 100%
  max-width: 1200px
  position: relative
  &-help
    position: absolute
    top: 22px
    right: 12px
    &:hover:after
      display: block
      position: absolute
      font-family: "Roboto"
      font-size: 12px
      color: $color-grey-400
      background-color: $color-grey-900
      border-radius: 2px
      width: max-content
      padding: 4px 8px
      top: 30px
      right: 0
      max-width: 400px
      z-index: 9
      content: "For full details click on the items in the table below."
  &-select-gateway
    margin-bottom: 1rem
  &-tabs
    list-style-type: none
    margin: 0
    padding: 0
    display: flex
    flex-direction: row
    justify-content: flex-start
    height: 24px
    margin-bottom: 1rem
    & li
      font-family: "Roboto"
      font-weight: 500
      padding-left: 1rem
      padding-right: 1rem
      &.active
        color: $color-blue-c3
        border-bottom: 1px solid $color-blue-c3
      &:hover
        cursor: pointer
.c3tab
  display: flex
  flex-direction: column
  flex-grow: 1
  &-filters
    display: flex
    .c3select
      max-width: 250px
      &:not(:first-of-type)
        margin-left: 16px
  &-info-dot
    width: 8px
    height: 8px
    display: inline-block
    border-radius: 50%
    margin: 0 .25rem
    &.is-complete
      background-color: $color-grey-500
    &.not-complete
      background-color: $color-green-500
    &.is-return
      background-color: $color-purple-500
    &.not-active
      background-color: $color-orange-500
    &.is-active
      background-color: $color-green-500
    &.has-error
      background-color: $color-red-500
.datatable
  font-size: 14px
  line-height: 16px
  border-collapse: collapse
  width: 100%
  tbody tr
    font-family: "Roboto"
    font-weight: 400
    &:hover, active
      background: $color-grey-900
      cursor: pointer
  tr
    height: 32px
    border-bottom: 2px solid $color-grey-800
  td, th
    text-align: left
  td
    color: $color-grey-500
  th
    color: $color-grey-000
  thead tr
    font-family: "Roboto"
    font-weight: 500
    height: 40px
    th
      font-weight: 500
.c3command
  background-color: $color-grey-900
  color: $color-grey-500
  padding: 8px
</style>
