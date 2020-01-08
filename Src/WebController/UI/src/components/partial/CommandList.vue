<template>
  <div class="c3CommandList" v-if="commands.length || displayEmpty">
    <h1 v-show="hasTitle">{{ title }}</h1>
    <template v-if="commands.length">
      <table class="datatable">
        <thead>
          <tr>
            <th>Command ID</th>
            <!-- <th>Status</th> -->
            <th>Command for</th>
            <th>ID</th>
          </tr>
        </thead>
        <tbody>
          <tr
            v-for="c3Command in commands"
            v-bind:key="c3Command.id"
            v-on:click="openModal(c3Command.id, 'COMMAND')"
          >
            <td class="c3link">
              <!-- <span
                class="c3tab-info-dot"
                :class="isCommandPending(c3Command)"
              ></span> -->
              {{ c3Command.id }}
            </td>
            <!-- <td>
              {{ isCommandPending(c3Command, true) }}
            </td> -->
            <td class="command-for">
              {{ commandType(c3Command).toLowerCase() }}
            </td>
            <td>
              {{ commandTypeId(c3Command) }}
            </td>
          </tr>
        </tbody>
      </table>
    </template>
    <template v-else-if="displayEmpty">
      No commands found...
    </template>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Prop, Mixins } from 'vue-property-decorator';

import { GetNodeKlassFn } from '@/store/C3Module';
import {
  NodeKlass,
  C3Node,
  C3Command,
  C3Gateway,
  nullNode
} from '@/types/c3types';

import C3 from '@/c3';
import Partial from '@/components/partial/Partial';

const C3CommandModule = namespace('c3CommandModule');

@Component
export default class CommandList extends Mixins(C3, Partial) {
  @Prop() public statusFilter!: string;
  @Prop() public commandForFilter!: string;

  @C3CommandModule.Getter public getCommands!: C3Command[];
  @C3CommandModule.Getter public getCommandCount!: number;

  get commands() {
    let commandsArray = this.getCommands;

    if (this.statusFilter === 'COMPLETE') {
      commandsArray = commandsArray.filter((c3Command: C3Command) => {
        return c3Command.isPending === false;
      });
    } else if (this.statusFilter === 'PENDING') {
      commandsArray = commandsArray.filter((c3Command: C3Command) => {
        return c3Command.isPending === true;
      });
    }

    if (this.commandForFilter !== 'ALL') {
      commandsArray = commandsArray.filter((c3Command: C3Command) => {
        return this.commandType(c3Command) === this.commandForFilter;
      });
    }

    this.$emit('count', commandsArray.length);
    return commandsArray;
  }
}
</script>

<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3CommandList
  margin-bottom: 24px
.command-for
  text-transform: capitalize
</style>
