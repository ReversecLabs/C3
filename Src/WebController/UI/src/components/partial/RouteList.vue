<template>
  <div class="c3route-list" v-if="(routes && routes.length) || displayEmpty">
    <h1 v-show="hasTitle">{{ title }}</h1>
    <template v-if="routes.length">
      <table class="datatable">
        <thead>
          <tr>
            <th>Route ID</th>
            <th>Destination Agent</th>
            <th>Outgoing Interface</th>
            <th>Receiving Interface</th>
            <th>Is Neighbour</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="route in routes" v-bind:key="route.destinationAgent">
            <td>{{ route.destinationAgent }}:{{ route.receivingInterface }}</td>
            <td>{{ route.destinationAgent }}</td>
            <td>{{ route.outgoingInterface }}</td>
            <td>{{ route.receivingInterface }}</td>
            <td>{{ route.isNeighbour ? 'Yes' : '' }}</td>
            <td style="position: relative;">
              <span class="c3route-list-more-btn icon more"></span>
              <ul class="c3route-list-menu">
                <li
                  class="c3route-list-menu-item"
                  @click="
                    sendCommand(
                      route.destinationAgent + ':' + route.receivingInterface
                    )
                  "
                >
                  Delete
                </li>
              </ul>
            </td>
          </tr>
        </tbody>
      </table>
    </template>
    <template v-else-if="displayEmpty">
      No routes found...
    </template>
  </div>
</template>

<script lang="ts">
import axios from 'axios';
import { namespace } from 'vuex-class';
import { Component, Prop, Mixins } from 'vue-property-decorator';

import { NodeKlass, C3Route } from '@/types/c3types';
import { GetRelayRoutesFn, GetRelayFn } from '@/store/C3Module';

import C3 from '@/c3';
import Partial from '@/components/partial/Partial';
import { GetCapabilityForFn } from '@/store/C3Capability';

const C3Module = namespace('c3Module');
const C3Capability = namespace('c3Capability');
const C3OptionsModule = namespace('optionsModule');

@Component
export default class RouteList extends Mixins(C3, Partial) {
  @Prop() public targetId!: string;
  @Prop() public parentId!: string;
  @Prop() public parentKlass!: NodeKlass;

  @C3Module.Getter public getRelay!: GetRelayFn;
  @C3Module.Getter public getGatewayRoutes!: C3Route[];
  @C3Module.Getter public getRelayRoutes!: GetRelayRoutesFn;

  @C3Capability.Getter public getCapabilityFor!: GetCapabilityForFn;

  @C3OptionsModule.Getter public getAPIBaseUrl!: string;

  get routes() {
    if (!this.targetId) {
      return this.getGatewayRoutes;
    }
    return this.getRelayRoutes(this.targetId);
  }

  get getCommandId() {
    const interfaceKlass = !!this.targetId ? 'RELAY' : 'GATEWAY';
    const capability = this.getCapabilityFor(
      'Command',
      interfaceKlass as NodeKlass
    );
    if (!!capability) {
      const com = capability.commands.find((c: any) => {
        return c.name === 'RemoveRoute';
      });
      return com.id;
    }
    return '';
  }

  get relay() {
    const r = this.getRelay(this.targetId);
    if (!r) {
      this.closeThisModal();
    }
    return r;
  }

  public sendCommand(routeToDelete: string): void {
    let data = null;

    if (!this.targetId) {
      data = {
        name: 'GatewayCommandGroup',
        data: {
          id: this.getCommandId,
          name: 'Command',
          command: 'RemoveRoute',
          arguments: [
            {
              type: 'string',
              name: 'RouteID',
              value: routeToDelete
            }
          ]
        }
      };
    } else {
      data = {
        name: 'RelayCommandGroup',
        data: {
          id: this.getCommandId,
          name: 'Command',
          command: 'RemoveRoute',
          arguments: [
            {
              type: 'string',
              name: 'RouteID',
              value: routeToDelete
            }
          ]
        }
      };
    }

    // POST /api/gateway/{gatewayId}/command
    // POST /api/gateway/{gatewayId}/relay/{relayId}/command

    let apiURL = '/api/gateway/';

    if (!!this.parentKlass && this.parentKlass === NodeKlass.Gateway) {
      apiURL = apiURL + `${this.parentId}/command`;
    }

    if (!!this.parentKlass && this.parentKlass === NodeKlass.Relay) {
      const relay = this.getRelay(this.parentId);
      if (!!relay) {
        apiURL = apiURL + `${relay.parentId}/relay/${this.parentId}/command`;
      } else {
        apiURL = apiURL + `${this.parentId}/command`;
      }
    }

    axios({
      url: apiURL,
      method: 'POST',
      baseURL: this.getAPIBaseUrl,
      data
    })
      .then(response => {
        this.addNotify({
          type: 'info',
          message: 'Command successfully sent...'
        });
        this.closeThisModal();
      })
      .catch(error => {
        const msg: string = 'Command NOT sent: ' + error.message;
        this.addNotify({
          type: 'error',
          message: msg
        });
        // tslint:disable-next-line:no-console
        console.error(error.message);
      });
  }
}
</script>

<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3route-list
  margin-bottom: 24px
  .datatable tbody tr:hover
    background: transparent
    cursor: default
  &-more-btn
    position: relative
    cursor: pointer
    float: right
  &-menu
    display: none
    flex-direction: column
    position: absolute
    right: 0
    top: 10px
    flex-direction: column
    padding: 0
    background: $color-grey-800
    box-shadow: 0px 12px 24px rgba(0, 0, 0, 0.15)
    border-radius: 2px
    list-style: none
    min-width: 180px
    z-index: 9
    &-item
      display: flex
      align-items: center
      font-size: 14px
      line-height: 16px
      color: $color-grey-000
      height: 32px
      padding: 0 8px
      border-radius: 2px
      &:hover
        background-color: $color-grey-700
        cursor: pointer
    &-divider
      height: 0
      width: 100
      border-bottom: 1px solid $color-grey-800
    &:hover
      display: flex
  &-more-btn:hover + .c3route-list-menu
    display: flex
</style>
