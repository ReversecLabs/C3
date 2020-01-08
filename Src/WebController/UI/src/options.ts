import {
  GatewayActive,
  GatewayError,
  RelayActive,
  RelayError,
  ChannelActive,
  ChannelReturn,
  ChannelError,
  PeripheralError,
  PeripheralActive,
  ConnectorActive,
  ConnectorError,
  GatewayInactive,
  RelayInactive,
  RelayGhost,
  NegotiationActive,
  NegotiationError
} from '@/components/assets/SvgIconsForVis';

export const GATEWAY: number = 10;
export const RELAY: number = 20;
export const CHANNEL: number = 30;
export const PERIPHERAL: number = 40;
export const CONNECTOR: number = 50;
export const NEGOTIATION_CHANNEL: number = 5;
export const ERROR: number = 1;
export const RETURN_CHANNEL: number = 2;
export const INACTIVE: number = 3;
export const GHOST: number = 5;

// The Vis Options for visualisation
export const VisOptions: any = {
  nodes: {
    font: {
      color: '#fff',
      background: '#222',
      size: 12,
      face: 'Roboto Mono',
      strokeWidth: 0,
      vadjust: 0
    },
    shadow: {
      enabled: false,
      color: 'rgba(23,223,115,1)',
      size: 20,
      x: 0,
      y: 0
    },
    widthConstraint: {
      maximum: 75
    },
    margin: {
      top: 0
    }
  },
  edges: {
    font: {
      color: '#fff',
      background: '#222',
      size: 12,
      face: 'Roboto Mono',
      strokeWidth: 0
    },
    color: {
      color: '#BDBDBD',
      highlight: '#0cf2a3'
    },
    smooth: false
  },
  groups: {
    // GATEWAY
    10: {
      shape: 'image',
      image: GatewayActive,
      size: 30
    },
    // GATEWAY + ERROR
    11: {
      shape: 'image',
      image: GatewayError,
      size: 30
    },
    // GATEWAY + INACTIVE
    13: {
      shape: 'image',
      image: GatewayInactive,
      size: 30
    },
    // GATEWAY + INACTIVE + ERROR
    14: {
      shape: 'image',
      image: GatewayError,
      size: 30
    },
    // RELAY
    20: {
      shape: 'image',
      image: RelayActive,
      size: 30
    },
    // RELAY + ERROR
    21: {
      shape: 'image',
      image: RelayError,
      size: 30
    },
    // RELAY + INACTIVE
    23: {
      shape: 'image',
      image: RelayInactive,
      size: 30
    },
    // RELAY + INACTIVE +ERROR
    24: {
      shape: 'image',
      image: RelayError,
      size: 30
    },
    // RELAY + GHOST
    25: {
      shape: 'image',
      image: RelayGhost,
      size: 30
    },
    // RELAY + GHOST + ERROR
    26: {
      shape: 'image',
      image: RelayError,
      size: 30
    },
    // RELAY + INACTIVE + GHOST
    28: {
      shape: 'image',
      image: RelayGhost,
      size: 30
    },
    // RELAY + INACTIVE  + GHOST + ERROR
    29: {
      shape: 'image',
      image: RelayError,
      size: 30
    },
    // CHANNEL
    30: {
      shape: 'image',
      image: ChannelActive,
      size: 20
    },
    // CHANNEL + ERROR
    31: {
      shape: 'image',
      image: ChannelError,
      size: 20
    },
    // CHANNEL + RETURN_CHANNEL
    32: {
      shape: 'image',
      image: ChannelReturn,
      size: 20
    },
    // CHANNEL + RETURN_CHANNEL + ERROR
    33: {
      shape: 'image',
      image: ChannelError,
      size: 20
    },
    // NEGOTIATION_CHANNEL
    35: {
      shape: 'image',
      image: NegotiationActive,
      size: 25
    },
    // NEGOTIATION_CHANNEL + ERROR
    36: {
      shape: 'image',
      image: NegotiationError,
      size: 25
    },
    // PERIPHERAL
    40: {
      shape: 'image',
      image: PeripheralActive,
      size: 20
    },
    // PERIPHERAL + ERROR
    41: {
      shape: 'image',
      image: PeripheralError,
      size: 20
    },
    // CONNECTOR
    50: {
      shape: 'image',
      image: ConnectorActive,
      size: 20
    },
    // CONNECTOR + ERROR
    51: {
      shape: 'image',
      image: ConnectorError,
      size: 20
    }
  },
  layout: {
    randomSeed: 921401,
    improvedLayout: true,
    hierarchical: {
      enabled: true,
      direction: 'LR',
      parentCentralization: true,
      blockShifting: true,
      levelSeparation: 150,
      treeSpacing: 200,
      nodeSpacing: 100,
      edgeMinimization: true,
      sortMethod: 'hubsize'
    }
  },
  physics: {
    enabled: true,
    solver: 'barnesHut',
    barnesHut: {
      gravitationalConstant: -4500,
      springLength: 100,
      springConstant: 0.01,
      damping: 0.1,
      avoidOverlap: 0
    },
    minVelocity: 0.45,
    stabilization: {
      enabled: true,
      iterations: 1000,
      updateInterval: 10,
      onlyDynamicEdges: false,
      fit: true
    }
  },
  interaction: {
    navigationButtons: true,
    keyboard: false
  }
};

// maximum toast shown
export const maximumToast: number = 3;

// the data refresh rate in milisecond
export const refreshInterval: number = 2000;

export const notifyLenght = 5000;
