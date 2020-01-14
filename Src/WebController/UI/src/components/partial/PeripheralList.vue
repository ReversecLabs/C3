<template>
  <div class="c3InterfaceList" v-if="peripherals.length || displayEmpty">
    <h1 v-show="hasTitle">{{ title }}</h1>
    <template v-if="peripherals.length">
      <table class="datatable">
        <thead>
          <tr>
            <th>Peripheral ID</th>
            <th>Name</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="peripheral in peripherals"
            v-bind:key="peripheral.id"
            v-on:click="openModal(peripheral.uid, peripheral.klass)"
          >
            <td class="c3link">{{ peripheral.id }}</td>
            <td>{{ interfaceTypeName(peripheral) }}</td>
          </tr>
        </tbody>
      </table>
    </template>
    <template v-else-if="displayEmpty">
      No peripherals found...
    </template>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Prop, Mixins } from 'vue-property-decorator';

import { NodeKlass } from '@/types/c3types';
import { GetInterfacesForFn } from '@/store/C3Module';

import C3 from '@/c3';
import Partial from '@/components/partial/Partial';

const C3Module = namespace('c3Module');

@Component
export default class PeripheralList extends Mixins(C3, Partial) {
  @Prop() public targetId!: string;

  @C3Module.Getter public getInterfacesFor!: GetInterfacesForFn;

  get peripherals() {
    if (!this.targetId) {
      return this.getInterfacesFor(NodeKlass.Peripheral, null);
    }
    return this.getInterfacesFor(NodeKlass.Peripheral, this.targetId);
  }
}
</script>

<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3InterfaceList
  margin-bottom: 24px
</style>
