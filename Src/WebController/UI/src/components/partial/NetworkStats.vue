<template>
  <div class="c3Stats">
    <p>
      <span>Relays</span>
      <span>{{ countRelays }}</span>
    </p>
    <p>
      <span>Channels</span>
      <span>{{ countChannels }}</span>
    </p>
    <p>
      <span>Connectors</span>
      <span>{{ countConnectors }}</span>
    </p>
    <p>
      <span>Peripherals</span>
      <span>{{ countPheripherals }}</span>
    </p>
    <p>
      <span>URL</span>
      <span>{{ url }}</span>
    </p>
    <p>
      <span>Port</span>
      <span>{{ port }}</span>
    </p>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Mixins } from 'vue-property-decorator';

import { GetInterfacesFn } from '@/store/C3Module';
import { GatewayHeader, NodeKlass, C3Node } from '@/types/c3types';

import C3 from '@/c3';

const C3Module = namespace('c3Module');
const C3OptionsModule = namespace('optionsModule');

@Component
export default class NetworkStats extends Mixins(C3) {
  @C3Module.Getter public getRelays!: C3Node[];
  @C3Module.Getter public getInterfaces!: GetInterfacesFn;

  @C3OptionsModule.Getter public getAPIUrl!: string;
  @C3OptionsModule.Getter public getAPIPort!: number;
  @C3OptionsModule.Getter public getRefreshInterval!: number;

  get url() {
    return this.getAPIUrl;
  }

  get port() {
    return this.getAPIPort;
  }

  get refreshInterval() {
    return this.getRefreshInterval;
  }

  get countRelays() {
    return this.getRelays.length;
  }

  get countChannels() {
    return this.getInterfaces([NodeKlass.Channel]).length;
  }

  get countConnectors() {
    return this.getInterfaces([NodeKlass.Connector]).length;
  }

  get countPheripherals() {
    return this.getInterfaces([NodeKlass.Peripheral]).length;
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3Stats
  display: flex
  flex-direction: column
  p
    display: flex
    justify-content: space-between
    align-items: center
    margin: 0
    font-size: 14px
    line-height: 16px
    height: 32px
    span
      max-width: 75%
      overflow: hidden
      text-overflow: ellipsis
      display: block
      white-space: nowrap
    &:last-of-type
      margin-bottom: 24px
</style>
