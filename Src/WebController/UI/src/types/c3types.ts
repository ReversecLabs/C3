export interface C3State {
  edges: C3Edge[];
  nodes: C3Node[];
  gateways: GatewayHeader[];
  gateway?: C3Gateway | null;
  relayTimestamps?: C3RelayTime[];
  mustRefresh?: boolean;
  lastGetHash: string;
}

export enum NodeKlass {
  Channel = 'CHANNEL',
  Connector = 'CONNECTOR',
  Gateway = 'GATEWAY',
  Interface = 'INTERFACE',
  Peripheral = 'PERIPHERAL',
  Relay = 'RELAY',
  Undefined = 'UNDEFINED'
}

export interface C3RelayTime {
  id: string;
  time: number;
}

export interface C3Node {
  id: string;
  uid: string;
  name?: string;
  klass: NodeKlass;
  buildId?: string;
  pending: boolean;
  isActive?: boolean;
  type: number;
  timestamp?: number;
  error: string | null;
  initialCommand?: any;
  propertiesText?: any;
  parentId: string | null;
  parentKlass: string | null;
  isReturnChannel?: boolean;
  isNegotiationChannel?: boolean;
  hostInfo?: C3HostInfo;
  [key: string]: any;
}

export const nullNode: C3Node = {
  uid: '',
  klass: NodeKlass.Undefined,
  id: '',
  name: 'Null Node',
  pending: false,
  isActive: false,
  type: 0,
  error: null,
  parentId: null,
  parentKlass: null,
  isReturnChannel: false,
  isNegotiationChannel: false,
  initialCommand: {},
  propertiesText: {}
};

export interface C3Edge {
  id: string;
  klass: NodeKlass;
  isNegotiationChannel?: boolean;
  length: number;
  dashes: boolean;
  from: string;
  to: string;
  color?: string;
  [key: string]: any;
}

export interface C3Interface {
  iid: string;
  type: number;
  error?: string;
  pending?: boolean;
  parentId?: string;
  initialCommand?: any;
  propertiesText?: any;
  isReturnChannel?: boolean;
  isNegotiationChannel?: boolean;
}

export interface C3Route {
  isNeighbour?: boolean;
  destinationAgent: string;
  outgoingInterface: string;
  receivingInterface: string;
}

export interface C3Relay {
  buildId: string;
  agentId: string;
  channels: C3Interface[];
  error?: string;
  initialCommand?: any;
  propertiesText?: any;
  name: string;
  pending: boolean;
  peripherals: C3Interface[];
  routes: C3Route[];
  isActive: boolean;
  timestamp?: number;
  hostInfo: C3HostInfo;
}

export interface C3HostInfo {
  computerName: string;
  userName: string;
  domain: string;
  osMajorVersion: number;
  osMinorVersion: number;
  osBuildNumber: number;
  osServicePackMajor: number;
  osServicePackMinor: number;
  osProductType: number;
  processId: number;
  isElevated: boolean;
  osVersion: string;
}

export interface GatewayHeader {
  agentId: string;
  buildId: string;
  name: string;
  isActive: boolean;
}

export interface C3Gateway {
  agentId: string;
  buildId: string;
  channels: C3Interface[];
  connectors: C3Interface[];
  error?: string;
  initialCommand?: any;
  propertiesText?: any;
  name: string;
  pending: boolean;
  peripherals: C3Interface[];
  relays: C3Relay[];
  routes: C3Route[];
  isActive: boolean;
  timestamp?: number;
}

interface C3Args {
  args: C3Opts[];
}

interface C3Opts {
  [key: string]: string;
}

export interface C3Command {
  name: string;
  id: string | number;
  isPending: boolean;
  data: C3Opts[] | C3Args;
  interfaceId?: string | number;
  relayAgentId?: string | number;
}

export interface C3Parent {
  agentId: string;
  parentType: string;
}

export interface FetchData {
  relayId?: string;
  gatewayId: string;
  interfaceId?: string;
}

export interface C3FieldDefault {
  name: string;
  type?: string;
  value: string;
}

export interface FormOptions {
  prefix: string;
  interface: string;
  arguments: C3FieldDefault[];
}

export interface SourceOptions {
  relay?: C3Node;
  interface?: C3Node;
}
export interface C3CommandCenterOptions {
  formDefault?: FormOptions;
  source?: SourceOptions;
  targetGroup?: string;
}
