<template>
  <div class="c3InterfaceList" v-if="relays.length || displayEmpty">
    <h1 v-show="hasTitle">{{ title }}</h1>
    <template v-if="relays.length">
      <table class="datatable">
        <thead>
          <tr>
            <th>Relay ID</th>
            <th>Name</th>
            <th>Build ID</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="(relay, index) in relays"
            v-bind:key="relay.id"
            v-show="index >= minIndex && index < maxIndex"
            v-on:click="openModal(relay.uid, relay.klass)"
          >
            <td class="c3link">
              <span
                class="c3tab-info-dot not-active"
                :class="{
                  'is-active': !!relay.isActive,
                  'has-error': !!relay.error
                }"
              ></span>
              {{ relay.id }}
            </td>
            <td>{{ relay.name }}</td>
            <td>{{ relay.buildId }}</td>
          </tr>
        </tbody>
      </table>
    </template>
    <template v-else-if="displayEmpty">
      No relays found...
    </template>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Prop, Mixins } from 'vue-property-decorator';

import { NodeKlass, C3Node } from '@/types/c3types';

import C3 from '@/c3';
import Partial from '@/components/partial/Partial';

const C3Module = namespace('c3Module');

@Component
export default class RelayList extends Mixins(C3, Partial) {
  @C3Module.Getter public getRelays!: C3Node[];

  get relays() {
    this.$emit('count', this.getRelays.length);
    return this.getRelays;
  }
}
</script>

<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3InterfaceList
  margin-bottom: 24px
</style>
