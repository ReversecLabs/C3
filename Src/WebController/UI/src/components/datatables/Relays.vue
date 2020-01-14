<template>
  <div class="c3tab">
    <RelayList :show-empty="true" @count="setCount($event)" />
    <DataTableFooter :results="getCount" />
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Mixins } from 'vue-property-decorator';

import { C3Node } from '@/types/c3types';

import C3 from '@/c3';
import RelayList from '@/components/partial/RelayList.vue';
import DataTableFooter from '@/components/datatables/DataTableFooter.vue';

const C3Module = namespace('c3Module');

@Component({
  components: {
    RelayList,
    DataTableFooter
  }
})
export default class RelaysTab extends Mixins(C3) {
  @C3Module.Getter public getRelays!: C3Node[];

  public rCount: number = 0;

  get getCount() {
    return this.rCount;
  }

  public setCount(n: number): void {
    this.rCount = n;
  }
}
</script>
