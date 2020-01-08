<template>
  <div class="c3modal-body" v-if="gateway !== null">
    <div class="c3modal-header" :class="{ 'has-error': !!gateway.error }">
      <h1>
        Gateway: <span>&nbsp;{{ gateway.name }} / {{ gateway.id }}</span>
      </h1>
      <div class="flex-row">
        <div class="details">
          <p>
            Build ID <span>{{ gateway.buildId }}</span>
          </p>
          <p>
            Start time <span>{{ unixTimeToString(gateway.timestamp) }}</span>
          </p>
        </div>
        <div class="actions">
          <button
            class="c3btn c3btn--grey"
            v-on:click="openModal('', 'CREATE_RELAY')"
          >
            New Relay
          </button>
        </div>
      </div>
      <p v-if="gateway.error && gateway.error !== ''" class="message-with-icon">
        <span class="icon warning"></span>
        Error: {{ gateway.error }}
      </p>
      <div class="flex-row">
        <NetworkStats style="width:250px;" />
        <div class="actions">
          <button
            class="c3btn c3btn--outline"
            v-on:click="openModal(gateway.id, 'COMMAND_CENTER')"
          >
            Command Center
          </button>
        </div>
      </div>
    </div>
    <div class="c3modal-details">
      <ChannelList :target-id="null" title="Channels" :show-empty="true" />
      <PheripheralList
        :target-id="null"
        title="Peripherals"
        :show-empty="true"
      />
      <ConnectorList title="Connectors" :show-empty="true" />
      <RouteList
        :target-id="null"
        :parent-id="gateway.id"
        parent-klass="GATEWAY"
        title="Routes"
        :show-empty="true"
      />
    </div>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Prop, Mixins } from 'vue-property-decorator';

import { C3Relay, C3Interface, NodeKlass, C3Node } from '@/types/c3types';

import C3 from '@/c3';
import RouteList from '@/components/partial/RouteList.vue';
import ChannelList from '@/components/partial/ChannelList.vue';
import NetworkStats from '@/components/partial/NetworkStats.vue';
import ConnectorList from '@/components/partial/ConnectorList.vue';
import PheripheralList from '@/components/partial/PeripheralList.vue';
import CommandCenterModal from '@/components/modals/CommandCenter.vue';

const C3Module = namespace('c3Module');

@Component({
  components: {
    RouteList,
    ChannelList,
    NetworkStats,
    ConnectorList,
    PheripheralList,
    CommandCenterModal
  }
})
export default class GatewayModal extends Mixins(C3) {
  public mounted(): void {
    (window as any).addEventListener('keydown', this.handleGlobalKeyDown, true);
  }

  public beforeDestroy(): void {
    (window as any).removeEventListener(
      'keydown',
      this.handleGlobalKeyDown,
      true
    );
  }
}
</script>
