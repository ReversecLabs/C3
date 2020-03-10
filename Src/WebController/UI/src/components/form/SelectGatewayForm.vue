<template>
  <div class="c3gateway-row">
    <Select
      legend="Gateways"
      v-on:change="selectGateway($event, activeGateway)"
      :selected="selectedGateway"
      :options="gateways"
      :border="true"
      :up="false"
    />
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Mixins } from 'vue-property-decorator';

import { FetchC3DataFn } from '@/store/C3Module';
import { C3Relay, C3Interface, GatewayHeader } from '@/types/c3types';

import C3 from '@/c3';
import Select from '@/components/form/Select.vue';

const C3Module = namespace('c3Module');

@Component({
  components: {
    Select
  }
})
export default class SelectGatewayForm extends Mixins(C3) {
  @C3Module.Action public fetchGateway!: FetchC3DataFn;

  @C3Module.Getter public getGateways!: GatewayHeader[];

  public activeGateway: string = '';

  get selectedGateway() {
    return this.activeGateway;
  }

  get gateways() {
    const gateways: GatewayHeader[] = this.getGateways;
    const g: any = {};

    gateways.forEach((gateway: GatewayHeader, index: number) => {
      g[gateway.agentId] = `${gateway.name} - ${gateway.agentId}`;
    });

    if (gateways.length > 0 && this.selectedGateway === '') {
      this.activeGateway = gateways[0].agentId;
      this.fetchGateway({ gatewayId: this.selectedGateway });
    }
    return g;
  }

  public selectGateway(id: string): void {
    this.activeGateway = id;
    this.changeGateway();
    this.addNotify({
      type: 'info',
      message: `Gateway [${this.selectedGateway}] selected...`
    });
  }

  public changeGateway(): void {
    this.fetchGateway({ gatewayId: this.selectedGateway });
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="sass">
.c3gateway-row
  button
    margin-left: 1rem
</style>
