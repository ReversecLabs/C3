<template>
  <div class="c3modal-body" v-if="relay !== undefined">
    <div class="c3modal-header" :class="{ 'has-error': !!relay.error }">
      <h1>
        Relay: <span>&nbsp;{{ relay.name }} / {{ relay.id }}</span>
      </h1>
      <div class="flex-row">
        <div class="details">
          <p>
            Parent
            <span
              class="c3link"
              v-on:click="openModal(relay.parentId, relay.parentKlass)"
            >
              <span class="capitalize"
                >{{ relay.parentKlass.toLowerCase() }} /
              </span>
              {{ relay.parentId }}
            </span>
          </p>

          <p>
            Build ID <span>{{ relay.buildId }}</span>
          </p>
          <p>
            Last seen <span>{{ unixTimeToString(relay.timestamp) }}</span>
          </p>
        </div>

        <div class="actions">
          <button
            class="c3btn c3btn--outline"
            v-on:click="openModal(relay.id, 'COMMAND_CENTER')"
          >
            Command Center
          </button>
        </div>
      </div>

      <div class="flex-row host-info">
        <div class="details">
          <p>
            <span class="details-title">Computer Name </span
            ><span class="details-value">{{
              relay.hostInfo.computerName
            }}</span>
          </p>
          <p>
            <span class="details-title">User Name </span
            ><span class="details-value">{{ relay.hostInfo.userName }}</span>
          </p>
          <p>
            <span class="details-title">Domain </span
            ><span class="details-value">{{
              relay.hostInfo.domain === '' ? '-' : relay.hostInfo.domain
            }}</span>
          </p>
          <p>
            <span class="details-title">processId </span
            ><span class="details-value">{{ relay.hostInfo.processId }}</span>
          </p>
          <p>
            <span class="details-title">is Elevated </span
            ><span class="details-value">{{ relay.hostInfo.isElevated }}</span>
          </p>
        </div>
        <div class="details">
          <p>
            <span class="details-title">OS Major Version </span
            ><span class="details-value">{{
              relay.hostInfo.osMajorVersion
            }}</span>
          </p>
          <p>
            <span class="details-title">OS Minor Version </span
            ><span class="details-value">{{
              relay.hostInfo.osMinorVersion
            }}</span>
          </p>
          <p>
            <span class="details-title">OS Build Number </span
            ><span class="details-value">{{
              relay.hostInfo.osBuildNumber
            }}</span>
          </p>
          <p>
            <span class="details-title">OS Service Pack Major </span
            ><span class="details-value">{{
              relay.hostInfo.osServicePackMajor
            }}</span>
          </p>
          <p>
            <span class="details-title">OS Service Pack Minor </span
            ><span class="details-value">{{
              relay.hostInfo.osServicePackMinor
            }}</span>
          </p>
          <p>
            <span class="details-title">OS Product Type </span
            ><span class="details-value">{{
              relay.hostInfo.osProductType
            }}</span>
          </p>
          <p>
            <span class="details-title">OS Version </span
            ><span class="details-value">{{ relay.hostInfo.osVersion }}</span>
          </p>
        </div>
      </div>
      <p v-if="relay.error && relay.error !== ''" class="message-with-icon">
        <span class="icon warning"></span>
        Error: {{ relay.error }}
      </p>
    </div>
    <div class="c3modal-details">
      <ChannelList :target-id="targetId" title="Channels" :show-empty="true" />
      <PheripheralList
        :target-id="targetId"
        title="Peripherals"
        :show-empty="true"
      />
      <RouteList
        :target-id="targetId"
        :parent-id="relay.id"
        parent-klass="RELAY"
        title="Routes"
        :show-empty="true"
      />
      <template v-if="JSON.stringify(relay.initialCommand) !== '{}'">
        <h1>Command</h1>
        <pre class="c3command">{{
          JSON.stringify(relay.initialCommand, null, 4)
        }}</pre>
      </template>
    </div>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Prop, Mixins } from 'vue-property-decorator';

import { C3Relay, C3Interface, NodeKlass } from '@/types/c3types';
import { GetRelayFn, GetInterfacesForFn } from '@/store/C3Module';

import C3 from '@/c3';
import RouteList from '@/components/partial/RouteList.vue';
import ChannelList from '@/components/partial/ChannelList.vue';
import PheripheralList from '@/components/partial/PeripheralList.vue';

const C3Module = namespace('c3Module');

@Component({
  components: {
    RouteList,
    ChannelList,
    PheripheralList
  }
})
export default class RelayModal extends Mixins(C3) {
  @Prop() public targetId!: string;

  @C3Module.Getter public getRelay!: GetRelayFn;

  get relay() {
    const r = this.getRelay(this.targetId);
    if (!r) {
      this.closeThisModal();
    }
    return r;
  }

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

<style lang="sass">
@import '~@/scss/colors.scss'
.c3modal
  .flex-row.host-info
    justify-content: flex-start
    .details
      padding-left: 16px
      display: flex
      flex-direction: column
      padding: 0 16px 0 0
      align-self: flex-start
      min-width: 300px
      p
        font-size: 14px
        line-height: 20px
        margin: 8px 0 0 0
        display: flex
        justify-content: space-between
        max-width: 300px
        span.details-title
          text-align: left
          min-width: 40%
        span.details-value
          text-align: end
        &:last-of-type
          margin-bottom: 16px
</style>
