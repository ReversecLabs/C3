<template>
  <div class="c3CommandList" v-if="c3Interfaces.length || displayEmpty">
    <h1 v-show="hasTitle">{{ title }}</h1>
    <template v-if="c3Interfaces.length">
      <table class="datatable">
        <thead>
          <tr>
            <th>Interface ID</th>
            <th>Type</th>
            <th>Name</th>
            <th>Channel Type</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="(c3Interface, index) in c3Interfaces"
            v-bind:key="c3Interface.uid"
            v-show="index >= minIndex && index < maxIndex"
            v-on:click="openModal(c3Interface.uid, c3Interface.klass)"
          >
            <td class="c3link">
              <span
                class="c3tab-info-dot"
                :class="{
                  'is-return': !!c3Interface.isReturnChannel,
                  'has-error': !!c3Interface.error
                }"
              ></span>
              {{ c3Interface.id }}
            </td>
            <td class="capitalize">{{ c3Interface.klass.toLowerCase() }}</td>
            <td>{{ interfaceTypeName(c3Interface) }}</td>
            <td>{{ interfaceType(c3Interface) }}</td>
          </tr>
        </tbody>
      </table>
    </template>
    <template v-else-if="displayEmpty">
      No interfaces found...
    </template>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Prop, Mixins, Provide } from 'vue-property-decorator';

import { GetNodeKlassFn, GetInterfacesFn } from '@/store/C3Module';
import {
  NodeKlass,
  C3Node,
  C3Command,
  C3Gateway,
  nullNode
} from '@/types/c3types';

import C3 from '@/c3';
import Partial from '@/components/partial/Partial';

const C3Module = namespace('c3Module');

@Component
export default class InterfaceList extends Mixins(C3, Partial) {
  @Prop() public returnChannelFilter!: string;
  @Prop() public interfaceTypeFilter!: string;
  @Prop() public negotiationChannelFilter!: string;

  @C3Module.Getter public getCommands!: C3Command[];
  @C3Module.Getter public getInterfaces!: GetInterfacesFn;

  get c3Interfaces() {
    let interfaces = [];
    if (this.interfaceTypeFilter === 'ALL') {
      interfaces = this.getInterfaces();
    } else {
      interfaces = this.getInterfaces([this.interfaceTypeFilter as NodeKlass]);
    }

    if (this.returnChannelFilter === 'YES') {
      interfaces = interfaces.filter((c3Node: C3Node) => {
        return !!c3Node.isReturnChannel;
      });
    } else if (this.returnChannelFilter === 'NO') {
      interfaces = interfaces.filter((c3Node: C3Node) => {
        return !c3Node.isReturnChannel;
      });
    }

    if (this.negotiationChannelFilter === 'YES') {
      interfaces = interfaces.filter((c3Node: C3Node) => {
        return !!c3Node.isNegotiationChannel;
      });
    } else if (this.negotiationChannelFilter === 'NO') {
      interfaces = interfaces.filter((c3Node: C3Node) => {
        return !c3Node.isNegotiationChannel;
      });
    }

    this.$emit('count', interfaces.length);
    return interfaces;
  }
}
</script>

<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3CommandList
  margin-bottom: 24px
.command-for
  text-transform: capitalize
</style>
