import { Module, GetterTree, MutationTree, ActionTree } from 'vuex';

import axios from 'axios';
import { RootState } from '@/types/store/RootState';
import { FetchData, NodeKlass } from '@/types/c3types';

const namespaced: boolean = true;

export interface InterfaceItem {
  type: number;
  name: string;
  klass: NodeKlass;
  commands: any;
}

export interface CapabilityState {
  capability: any;
  interfaceList: InterfaceItem[];
}

// State

export const state: CapabilityState = {
  capability: {},
  interfaceList: []
};

// Getters
export type GetTypeNameForInterfaceFn = (t: number, k: NodeKlass) => string;
export type GetTypesForInterfaceKlassFn = (k: NodeKlass) => InterfaceItem[];
export type GetCapabilityForFn = (
  t: string,
  k: NodeKlass
) => InterfaceItem | undefined;
export type GetCommandGroupForFn = (k: NodeKlass) => any;
export type GetCommandTargetForFn = (
  commandName: string,
  nodeKlass: NodeKlass,
  currentType?: string | number
) => any;

export const getters: GetterTree<CapabilityState, RootState> = {
  getCommandGroupFor: capabilityState => (nodeKlass: NodeKlass): any => {
    let commands: any = {};

    switch (nodeKlass) {
      case NodeKlass.Gateway:
        if (capabilityState.capability && capabilityState.capability.commands) {
          commands = capabilityState.capability.commands;
        }
        break;
      case NodeKlass.Relay:
        if (
          capabilityState.capability &&
          capabilityState.capability.relayCommands
        ) {
          commands = capabilityState.capability.relayCommands.commands;
        }
        break;
      case NodeKlass.Channel:
        if (
          capabilityState.capability &&
          capabilityState.capability.channelCommands
        ) {
          commands = capabilityState.capability.channelCommands.commands;
        }
        break;
      case NodeKlass.Peripheral:
        if (
          capabilityState.capability &&
          capabilityState.capability.peripheralCommands
        ) {
          commands = capabilityState.capability.peripheralCommands.commands;
        }
        break;
      case NodeKlass.Connector:
        if (
          capabilityState.capability &&
          capabilityState.capability.connectorCommands
        ) {
          commands = capabilityState.capability.connectorCommands.commands;
        }
        break;
    }

    const options: any = {};
    if (commands.length !== undefined) {
      commands.forEach((element: any) => {
        const option = element.name;
        options[option] = option;
      });
    }

    return options;
  },

  getCommandTargetFor: capabilityState => (
    commandName: string,
    nodeKlass: NodeKlass,
    currentType?: number | string
  ): any => {
    let commands: any = {};

    switch (nodeKlass) {
      case NodeKlass.Gateway:
        if (capabilityState.capability && capabilityState.capability.commands) {
          commands = capabilityState.capability.commands;
        }
        break;
      case NodeKlass.Relay:
        if (
          capabilityState.capability &&
          capabilityState.capability.relayCommands
        ) {
          commands = capabilityState.capability.relayCommands.commands;
        }
        break;
      case NodeKlass.Channel:
        if (
          capabilityState.capability &&
          capabilityState.capability.channelCommands
        ) {
          commands = capabilityState.capability.channelCommands.commands;
        }
        break;
      case NodeKlass.Peripheral:
        if (
          capabilityState.capability &&
          capabilityState.capability.peripheralCommands
        ) {
          commands = capabilityState.capability.peripheralCommands.commands;
        }
        break;
      case NodeKlass.Connector:
        if (
          capabilityState.capability &&
          capabilityState.capability.connectorCommands
        ) {
          commands = capabilityState.capability.connectorCommands.commands;
        }
        break;
    }

    let commandList: any = {};
    if (commands.length !== undefined) {
      commandList = commands.find((command: any) => {
        return command.name === commandName;
      });
    }

    const options: any = {};

    if (commandList && commandList.arguments) {
      const form = commandList.arguments.find((commandItem: any) => {
        return commandItem.type === 'form';
      });

      form.defaultValue.forEach((option: any) => {
        if (currentType === undefined) {
          options[option.replace(/:/g, '_')] = option.split(':')[2];
        } else {
          const optionType = option.split(':')[1];
          if (optionType === currentType) {
            options[option.replace(/:/g, '_')] = option.split(':')[2];
          }
        }
      });
    }

    return options;
  },

  getTypeNameForInterface: capabilityState => (
    t: number,
    k: NodeKlass
  ): string | undefined => {
    const item = capabilityState.interfaceList.find((i: InterfaceItem) => {
      return '' + i.type === '' + t; // && i.klass === k;
    });
    if (item !== undefined) {
      return item.name;
    }
    return '';
  },

  getTypesForInterfaceKlass: capabilityState => (
    k: NodeKlass
  ): InterfaceItem[] => {
    return capabilityState.interfaceList.filter((i: InterfaceItem) => {
      return i.klass === k;
    });
  },

  getCapabilityFor: capabilityState => (
    n: string,
    k: NodeKlass
  ): InterfaceItem | undefined => {
    return capabilityState.interfaceList.find((i: InterfaceItem) => {
      return i.name === n && i.klass === k;
    });
  }
};

// Mutations

export const mutations: MutationTree<CapabilityState> = {
  updateCapability(capabilityState, c: any) {
    capabilityState.interfaceList = [];
    capabilityState.capability = c;
  },

  populateList(capabilityState) {
    const getItem = (i: string) => {
      if (capabilityState.capability && capabilityState.capability[i]) {
        capabilityState.capability[i].forEach((element: InterfaceItem) => {
          const item: any = {
            type: element.type,
            name: element.name,
            commands: element.commands
          };

          switch (i) {
            case 'channels':
              item.klass = NodeKlass.Channel;
              break;
            case 'connectors':
              item.klass = NodeKlass.Connector;
              break;
            case 'peripherals':
              item.klass = NodeKlass.Peripheral;
              break;
            case 'gateway':
              item.klass = NodeKlass.Gateway;
              break;
            case 'relay':
              item.klass = NodeKlass.Relay;
              break;
          }

          capabilityState.interfaceList.push(item);
        });
      }
    };

    getItem('channels');
    getItem('connectors');
    getItem('peripherals');
    getItem('gateway');
    getItem('relay');
  }
};

// Actions

const actions: ActionTree<CapabilityState, RootState> = {
  fetchCapability(context, d: FetchData): void {
    if (d.gatewayId) {
      const url = `/api/gateway/${d.gatewayId}/capability`;
      const baseURL = `${context.rootGetters['optionsModule/getAPIUrl']}:${context.rootGetters['optionsModule/getAPIPort']}`;
      axios
        .get(url, { baseURL })
        .then(response => {
          context.commit('updateCapability', response.data);
          context.commit('populateList', response.data);
        })
        .catch(error => {
          context.dispatch(
            'notifyModule/insertNotify',
            { type: 'error', message: error.message },
            { root: true }
          );
          // tslint:disable-next-line:no-console
          console.error(error.message);
        });
    } else {
      context.dispatch(
        'notifyModule/insertNotify',
        { type: 'error', message: 'missing: gatewayId' },
        { root: true }
      );
      // tslint:disable-next-line:no-console
      console.error('missing: gatewayId');
    }
  }
};

export const c3Capability: Module<CapabilityState, RootState> = {
  namespaced,
  state,
  getters,
  mutations,
  actions
};
