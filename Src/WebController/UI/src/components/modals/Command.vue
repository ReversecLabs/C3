<template>
  <div class="c3modal-body" v-if="c3Command !== undefined">
    <div class="c3modal-details">
      <h1>
        Command Details
      </h1>
      <table class="datatable">
        <thead>
          <tr>
            <th>Command ID</th>
            <th>Status</th>
            <th>Command for</th>
            <th>ID</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-on:click="
              openModal(InterfaceUID(c3Command), commandType(c3Command))
            "
          >
            <td>
              <span
                class="c3tab-pending"
                :class="isCommandPending(c3Command)"
              ></span>
              {{ c3Command.id }}
            </td>
            <td>
              {{ isCommandPending(c3Command, true) }}
            </td>
            <td class="hover-link command-for">
              {{ commandType(c3Command).toLowerCase() }}
            </td>
            <td>
              {{ commandTypeId(c3Command) }}
            </td>
          </tr>
        </tbody>
      </table>
      <pre class="c3command">{{ JSON.stringify(c3Command, null, 4) }}</pre>
    </div>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Prop, Mixins } from 'vue-property-decorator';

import { Notify } from '@/store/NotifyModule';
import { GetCommandFn } from '@/store/C3Module';
import {
  C3Interface,
  C3Gateway,
  C3Relay,
  NodeKlass,
  C3Command,
  C3Node
} from '@/types/c3types';

import C3 from '@/c3';

const C3CommandModule = namespace('c3CommandModule');
const nodeKlass = NodeKlass;

@Component
export default class CommandModal extends Mixins(C3) {
  @Prop() public targetId!: string;

  @C3CommandModule.Getter public getCommand!: GetCommandFn;

  get c3Command() {
    const target = this.getCommand(this.targetId);
    if (!target) {
      this.closeThisModal();
      this.addNotify({
        type: 'error',
        message: `The Commandyou looking for: ${this.targetId}, not exist.`
      });
    }
    return target;
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

  public InterfaceUID(c: C3Command): string | number {
    if (!!c.interfaceId) {
      if (!!c.relayAgentId) {
        return c.interfaceId + '-' + c.relayAgentId;
      }
      return c.interfaceId + '-' + this.gateway.id;
    }
    if (!!c.relayAgentId) {
      return c.relayAgentId;
    }
    return this.gateway.id;
  }
}
</script>

<style scoped lang="sass">
@import '~@/scss/colors.scss'
tr:hover .hover-link
  color: $color-blue-c3
.command-for
  text-transform: capitalize
</style>
