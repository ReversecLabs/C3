<template>
  <div class="c3InterfaceList" v-if="channels.length || displayEmpty">
    <h1 v-show="hasTitle">{{ title }}</h1>
    <template v-if="channels.length">
      <table class="datatable">
        <thead>
          <tr>
            <th>Channel ID</th>
            <th>Name</th>
            <th>Channel Type</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="channel in channels"
            v-bind:key="channel.id"
            v-on:click="openModal(channel.uid, channel.klass)"
          >
            <td class="c3link">{{ channel.id }}</td>
            <td>{{ interfaceTypeName(channel) }}</td>
            <td>{{ interfaceType(channel) }}</td>
          </tr>
        </tbody>
      </table>
    </template>
    <template v-else-if="displayEmpty">
      No channels found...
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
export default class ChannelList extends Mixins(C3, Partial) {
  @Prop() public targetId!: string;

  @C3Module.Getter public getInterfacesFor!: GetInterfacesForFn;

  get channels() {
    if (!this.targetId) {
      return this.getInterfacesFor(NodeKlass.Channel, null);
    }
    return this.getInterfacesFor(NodeKlass.Channel, this.targetId);
  }
}
</script>

<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3InterfaceList
  margin-bottom: 24px
</style>
