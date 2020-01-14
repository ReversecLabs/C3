<template>
  <div class="c3tab">
    <div class="c3tab-filters">
      <Select
        key="type-filter"
        legend="Filter by type"
        v-on:change="selectInterfaceType($event, interfaceType)"
        :selected="selectedInterfaceType"
        :options="{
          ALL: 'All',
          CHANNEL: 'Channel',
          PERIPHERAL: 'Peripheral',
          CONNECTOR: 'Connector'
        }"
        :border="true"
        :up="false"
      />
      <Select
        key="return-channel-filter"
        legend="Filter by Return Channel"
        v-on:change="selectReturnChannel($event, returnChannel)"
        :selected="selectedReturnChannel"
        :options="{ ALL: 'All', YES: 'Yes', NO: 'No' }"
        :border="true"
        :up="false"
        :disabled="isChannelOrAllForDisabled"
      />
      <Select
        key="negotiation-channel-filter"
        legend="Filter by Negotiation Channel"
        v-on:change="selectNegotiationChannel($event, negotiationChannel)"
        :selected="selectedNegotiationChannel"
        :options="{ ALL: 'All', YES: 'Yes', NO: 'No' }"
        :border="true"
        :up="false"
        :disabled="isChannelOrAllForDisabled"
      />
    </div>
    <InterfaceList
      :show-empty="true"
      :return-channel-filter="selectedReturnChannel"
      :negotiation-channel-filter="selectedNegotiationChannel"
      :interface-type-filter="selectedInterfaceType"
      @count="setCount($event)"
    />
    <DataTableFooter :results="getCount" />
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Mixins } from 'vue-property-decorator';

import { c3Module, GetInterfacesFn } from '@/store/C3Module';
import { C3Interface, NodeKlass, C3Node } from '@/types/c3types';

import C3 from '@/c3';
import Select from '@/components/form/Select.vue';
import InterfaceList from '@/components/partial/InterfaceList.vue';
import DataTableFooter from '@/components/datatables/DataTableFooter.vue';

const C3Module = namespace('c3Module');

@Component({
  components: {
    Select,
    InterfaceList,
    DataTableFooter
  }
})
export default class InterfacesTab extends Mixins(C3) {
  public iCount = 0;
  public interfaceByType: string = 'ALL';
  public returnChannel: string = 'ALL';
  public negotiationChannel: string = 'ALL';

  get getCount() {
    return this.iCount;
  }

  get selectedInterfaceType() {
    return this.interfaceByType;
  }

  get selectedReturnChannel() {
    return this.returnChannel;
  }

  get selectedNegotiationChannel() {
    return this.negotiationChannel;
  }

  get isChannelOrAllForDisabled() {
    const isChannel =
      this.selectedInterfaceType === 'ALL' ||
      this.selectedInterfaceType === 'CHANNEL';
    if (!isChannel) {
      this.selectReturnChannel('NO');
      this.selectNegotiationChannel('NO');
    }
    return isChannel ? false : true;
  }

  public setCount(emitedCountNumber: number): void {
    this.iCount = emitedCountNumber;
  }

  public selectInterfaceType(newtype: string) {
    if (
      (this.interfaceByType === 'PERIPHERAL' ||
        this.interfaceByType === 'CONNECTOR') &&
      (newtype === 'ALL' || newtype === 'CHANNEL')
    ) {
      this.selectReturnChannel('ALL');
      this.selectNegotiationChannel('ALL');
    }
    this.interfaceByType = newtype;
  }

  public selectReturnChannel(filterReturnChannel: string) {
    this.returnChannel = filterReturnChannel;
  }

  public selectNegotiationChannel(filterNegotiationChannel: string) {
    this.negotiationChannel = filterNegotiationChannel;
  }
}
</script>
