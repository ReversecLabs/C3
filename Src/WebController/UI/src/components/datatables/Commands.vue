<template>
  <div class="c3tab">
    <!-- Filters turned off, because the back-end not support filtering at the moment. -->
    <!-- <div class="c3tab-filters">
      <Select
        key="command-status-filter"
        legend="Filter status"
        v-on:change="selectCommandStatus($event, commandStatus)"
        :selected="selectedCommandStatus"
        :options="{'ALL': 'All', 'COMPLETE': 'Complete', 'PENDING': 'Pending'}"
        :border="true"
        :up="false"
        v-show="false"
      />
      <Select
        key="command-for-filter"
        legend="Filter Command for"
        v-on:change="selectCommandFor($event, commandFor)"
        :selected="selectedCommandFor"
        :options="{
          'ALL': 'All',
          'GATEWAY': 'Gateway',
          'RELAY': 'Relay',
          'CHANNEL': 'Channel',
          'PERIPHERAL': 'Peripheral',
          'CONNECTOR': 'Connector',
        }"
        :border="true"
        :up="false"
        v-show="false"
      />
    </div> -->
    <CommandList
      :show-empty="true"
      :status-filter="selectedCommandStatus"
      :command-for-filter="selectedCommandFor"
    />
    <DataTableFooter :results="getCount" />
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Mixins, Watch } from 'vue-property-decorator';

import { C3Node, C3Command } from '@/types/c3types';

import C3 from '@/c3';
import Select from '@/components/form/Select.vue';
import CommandList from '@/components/partial/CommandList.vue';
import DataTableFooter from '@/components/datatables/DataTableFooter.vue';
import { FetchC3CommandFn } from '@/store/C3Command';
import { SetActualPageFn } from '@/store/PaginateModule';

const PaginateModule = namespace('paginateModule');
const C3CommandModule = namespace('c3CommandModule');

@Component({
  components: {
    Select,
    CommandList,
    DataTableFooter
  }
})
export default class CommandsTab extends Mixins(C3) {
  @C3CommandModule.Getter public getCommandCount!: number;

  @C3CommandModule.Action public fetchCommands!: FetchC3CommandFn;

  @PaginateModule.Getter public getActualPage!: number;
  @PaginateModule.Getter public getLastChange!: number;
  @PaginateModule.Getter public getItemPerPage!: number;

  @PaginateModule.Mutation public setActualPage!: SetActualPageFn;

  // public commandCount: number = 0;
  public commandFor: string = 'ALL';
  public commandStatus: string = 'ALL';

  get getCount() {
    return this.getCommandCount;
  }

  get selectedCommandFor() {
    return this.commandFor;
  }

  get selectedCommandStatus() {
    return this.commandStatus;
  }

  // Command count set by the back-end response. No filtering, so the results count won't change.
  // public setCount(count: number): void {
  //   this.commandCount = count;
  // }

  // If the actual page or item per page change: fetch the command logs
  @Watch('getLastChange')
  public onGetLastChange(value: any, oldValue: any) {
    this.fetchCommands(this.gateway.id);
  }

  public selectCommandFor(r: string) {
    this.commandFor = r;
  }

  public selectCommandStatus(t: string) {
    this.commandStatus = t;
  }
}
</script>
