<template>
  <div class="c3InterfaceList" v-if="connectors.length || displayEmpty">
    <h1 v-show="hasTitle">{{ title }}</h1>
    <template v-if="connectors.length">
      <table class="datatable">
        <thead>
          <tr>
            <th>Connector ID</th>
            <th>Name</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="connector in connectors"
            v-bind:key="connector.id"
            v-on:click="openModal(connector.uid, connector.klass)"
          >
            <td class="c3link">{{ connector.id }}</td>
            <td>{{ interfaceTypeName(connector) }}</td>
          </tr>
        </tbody>
      </table>
    </template>
    <template v-else-if="displayEmpty">
      No connectors found...
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
export default class ConnectorList extends Mixins(C3, Partial) {
  @C3Module.Getter public getInterfacesFor!: GetInterfacesForFn;

  get connectors() {
    // Only Gateway can have a connector...
    return this.getInterfacesFor(NodeKlass.Connector, null);
  }
}
</script>

<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3InterfaceList
  margin-bottom: 24px
</style>
