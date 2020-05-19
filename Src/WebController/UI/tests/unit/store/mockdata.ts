import { C3Node, NodeKlass } from './../../../src/types/c3types';

export const gateways = ['a1d0'];

export const nodes: C3Node[] = [
  {
    uid: 'a1d0',
    klass: NodeKlass.Gateway,
    id: 'a1d0',
    buildId: 'b1d0',
    name: 'gateway',
    pending: false,
    isActive: true,
    type: 0,
    error: null,
    parentId: null,
    parentKlass: null,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: '11d1-a1d0',
    klass: NodeKlass.Channel,
    id: '11d1',
    pending: false,
    isActive: true,
    type: 0,
    error: null,
    parentId: 'a1d0',
    isReturnChannel: false,
    parentKlass: NodeKlass.Gateway,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: 'c1d0-a1d0',
    klass: NodeKlass.Connector,
    id: 'c1d0',
    pending: false,
    isActive: true,
    type: 0,
    error: null,
    parentId: 'a1d0',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: 'c1d1-a1d0',
    klass: NodeKlass.Connector,
    id: 'c1d1',
    pending: false,
    isActive: true,
    type: 1,
    error: 'some connector error',
    parentId: 'a1d0',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: 'a1d1',
    klass: NodeKlass.Relay,
    id: 'a1d1',
    buildId: 'b1d1',
    name: 'alpha',
    pending: false,
    isActive: true,
    type: 99,
    error: null,
    parentId: 'a1d0',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: '11d0-a1d1',
    klass: NodeKlass.Channel,
    id: '11d0',
    pending: false,
    isActive: true,
    type: 0,
    error: null,
    parentId: 'a1d1',
    isReturnChannel: true,
    parentKlass: NodeKlass.Relay,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: '11d1-a1d1',
    klass: NodeKlass.Channel,
    id: '11d1',
    pending: false,
    isActive: true,
    type: 1,
    error: null,
    parentId: 'a1d1',
    isReturnChannel: false,
    parentKlass: NodeKlass.Relay,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: '11d3-a1d1',
    klass: NodeKlass.Channel,
    id: '11d3',
    pending: false,
    isActive: true,
    type: 0,
    error: null,
    parentId: 'a1d1',
    isReturnChannel: false,
    parentKlass: NodeKlass.Relay,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: '11d4-a1d1',
    klass: NodeKlass.Channel,
    id: '11d4',
    pending: false,
    isActive: true,
    type: 1,
    error: null,
    parentId: 'a1d1',
    isReturnChannel: false,
    parentKlass: NodeKlass.Relay,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: 'e1d1-a1d1',
    klass: NodeKlass.Peripheral,
    id: 'e1d1',
    pending: false,
    isActive: true,
    type: 1,
    error: null,
    parentId: 'a1d1',
    parentKlass: NodeKlass.Relay,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: 'e1d0-a1d1',
    klass: NodeKlass.Peripheral,
    id: 'e1d0',
    pending: false,
    isActive: true,
    type: 0,
    error: null,
    parentId: 'a1d1',
    parentKlass: NodeKlass.Relay,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: 'a1d2',
    klass: NodeKlass.Relay,
    id: 'a1d2',
    buildId: 'b1d2',
    name: 'beta',
    pending: false,
    isActive: true,
    type: 99,
    error: 'some relay error',
    parentId: 'a1d0',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: '11d2-a1d2',
    klass: NodeKlass.Channel,
    id: '11d2',
    pending: false,
    isActive: true,
    type: 1,
    error: 'some channel error',
    parentId: 'a1d2',
    isReturnChannel: false,
    parentKlass: NodeKlass.Relay,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: '11d1-a1d2',
    klass: NodeKlass.Channel,
    id: '11d1',
    pending: false,
    isActive: true,
    type: 0,
    error: null,
    parentId: 'a1d2',
    isReturnChannel: false,
    parentKlass: NodeKlass.Relay,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: '11d0-a1d2',
    klass: NodeKlass.Channel,
    id: '11d0',
    pending: false,
    isActive: true,
    type: 1,
    error: null,
    parentId: 'a1d2',
    isReturnChannel: true,
    parentKlass: NodeKlass.Relay,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: 'e1d3-a1d2',
    klass: NodeKlass.Peripheral,
    id: 'e1d3',
    pending: false,
    isActive: true,
    type: 0,
    error: 'some peripheral error',
    parentId: 'a1d2',
    parentKlass: NodeKlass.Relay,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: 'a1d3',
    klass: NodeKlass.Relay,
    id: 'a1d3',
    buildId: 'b1d3',
    name: 'charlie',
    pending: false,
    isActive: true,
    type: 99,
    error: null,
    parentId: 'a1d0',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: '11d0-a1d3',
    klass: NodeKlass.Channel,
    id: '11d0',
    pending: false,
    isActive: true,
    type: 1,
    error: null,
    parentId: 'a1d3',
    isReturnChannel: true,
    parentKlass: NodeKlass.Relay,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: '11d1-a1d3',
    klass: NodeKlass.Channel,
    id: '11d1',
    pending: false,
    isActive: true,
    type: 1,
    error: null,
    parentId: 'a1d3',
    isReturnChannel: false,
    parentKlass: NodeKlass.Relay,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: 'a1d4',
    klass: NodeKlass.Relay,
    id: 'a1d4',
    buildId: 'b1d4',
    name: 'denis',
    pending: false,
    isActive: true,
    type: 0,
    error: null,
    parentId: 'a1d0',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  },
  {
    uid: 'e1d4-a1d4',
    klass: NodeKlass.Peripheral,
    id: 'e1d4',
    pending: false,
    isActive: true,
    type: 1,
    error: null,
    parentId: 'a1d4',
    parentKlass: NodeKlass.Relay,
    initialCommand: {
      relayAgentId: 'a1d4',
      interfaceId: 'e1d4',
      id: 5,
      name: 'RelayInterfaceCommand',
      data: {
        args: [
          {
            arg1: 'val1'
          }
        ],
        opt: 'optval'
      },
      isPending: true
    }
  }
];

export const gateway = {
  '//comment': 'gateway',
  agentId: 'a1d0',
  buildId: '1',
  name: 'gateway',
  pending: 'false',
  isActive: 'true',
  error: '',
  channels: [
    {
      iid: '11d1',
      type: '1',
      pending: 'true',
      error: '',
      parentId: '0101',
      parentType: 'gateway'
    }
  ],
  peripherals: [
    {
      pending: 'true',
      error: '',
      iid: '11d1',
      type: '1'
    }
  ],
  routes: [
    {
      outgoingInterface: '11d1',
      destinationAgent: 'a1d0',
      receivingInterface: '11d0',
      isNeighbour: true
    },
    {
      outgoingInterface: '11d1',
      destinationAgent: 'a1d1',
      receivingInterface: '11d0'
    },
    {
      outgoingInterface: '11d1',
      destinationAgent: 'a1d2',
      receivingInterface: '11d0'
    },
    {
      outgoingInterface: '11d1',
      destinationAgent: 'a1d3',
      receivingInterface: '11d0'
    },
    {
      outgoingInterface: '11d1',
      destinationAgent: 'a1d2',
      receivingInterface: '11d1'
    }
  ],
  connectors: [],
  relays: [
    {
      buildId: 'b1d0',
      agentId: 'a1d0',
      name: 'delta',
      pending: 'false',
      error: '',
      channels: [
        {
          iid: '11d0',
          type: '1',
          pending: 'false',
          error: '',
          isReturnChannel: true,
          parentId: 'a1d0',
          parentType: 'relay'
        },
        {
          iid: '11d1',
          type: '2',
          pending: 'true',
          error: '',
          parentId: 'a1d0',
          parentType: 'relay'
        },
        {
          iid: '11d3',
          type: '1',
          pending: 'false',
          error: '',
          parentId: 'a1d0',
          parentType: 'relay'
        },
        {
          iid: '11d4',
          type: '1',
          pending: 'false',
          error: '',
          parentId: 'a1d0',
          parentType: 'relay'
        }
      ],
      peripherals: [
        {
          iid: '11d1',
          type: '1',
          pending: 'true',
          error: ''
        }
      ],
      routes: [
        {
          outgoingInterface: '11d1',
          destinationAgent: 'a1d1',
          receivingInterface: '11d0',
          isNeighbour: true
        },
        {
          outgoingInterface: '11d1',
          destinationAgent: 'a1d2',
          receivingInterface: '11d0'
        },
        {
          outgoingInterface: '11d3',
          destinationAgent: 'a1d3',
          receivingInterface: '11d0',
          isNeighbour: true
        },
        {
          outgoingInterface: '11d4',
          destinationAgent: 'a1d2',
          receivingInterface: '11d1',
          isNeighbour: true
        }
      ]
    },
    {
      buildId: 'b1d1',
      agentId: 'a1d1',
      name: 'charlie',
      pending: 'false',
      error: '',
      channels: [
        {
          iid: '11d0',
          type: '1',
          pending: 'false',
          error: '',
          parentId: 'a1d1',
          parentType: 'relay'
        },
        {
          iid: '11d1',
          type: '2',
          pending: 'true',
          error: '',
          isReturnChannel: true,
          parentId: 'a1d1',
          parentType: 'relay'
        },
        {
          iid: '11d2',
          type: '1',
          pending: 'false',
          error: '',
          parentId: 'a1d1',
          parentType: 'relay'
        }
      ],
      peripherals: [
        {
          iid: '11d1',
          type: '1',
          pending: 'true',
          error: ''
        }
      ],
      routes: [
        {
          outgoingInterface: '11d2',
          destinationAgent: 'a1d2',
          receivingInterface: '11d0',
          isNeighbour: true
        }
      ]
    },
    {
      buildId: 'b1d2',
      agentId: 'a1d2',
      name: 'bravo',
      pending: 'false',
      error: '',
      channels: [
        {
          iid: '11d0',
          type: '1',
          pending: 'false',
          error: '',
          parentId: 'a1d2',
          parentType: 'relay'
        },
        {
          iid: '11d1',
          type: '2',
          pending: 'true',
          error: '',
          isReturnChannel: true,
          parentId: 'a1d2',
          parentType: 'relay'
        }
      ],
      peripherals: [
        {
          iid: '11d1',
          type: '1',
          pending: 'true',
          error: ''
        }
      ],
      routes: []
    },
    {
      buildId: 'b1d3',
      agentId: 'a1d3',
      name: 'alpha',
      pending: 'false',
      error: '',
      channels: [
        {
          iid: '11d0',
          type: '1',
          pending: 'false',
          error: '',
          parentId: 'a1d3',
          parentType: 'relay'
        }
      ],
      peripherals: [
        {
          iid: '11d1',
          type: '1',
          pending: 'true',
          error: '',
          isReturnChannel: true
        }
      ],
      routes: []
    }
  ]
};

export const capability = {
  connectors: [
    {
      type: 0,
      name: 'MockServer',
      commands: [
        {
          name: 'Create',
          arguments: []
        }
      ],
      description: '...'
    },
    {
      type: 1,
      name: 'TeamServer',
      commands: [
        {
          name: 'Create',
          arguments: [
            {
              type: 'ip',
              name: 'Address',
              description: 'Listening post address'
            },
            {
              type: 'uint16',
              name: 'Port',
              description: 'Listening post port'
            }
          ]
        }
      ]
    }
  ],
  relayCommands: {
    commands: [
      {
        name: 'AddPeripheral',
        arguments: [
          {
            type: 'form',
            name: 'Peripheral type',
            defaultValue: [
              'peripherals:Beacon:Create',
              'peripherals:Mock:Create'
            ],
            description: '...'
          }
        ]
      },
      {
        name: 'AddChannel',
        arguments: [
          {
            type: 'form',
            name: 'Channel type',
            defaultValue: [
              'channels:NamedPipe:Create',
              'channels:EwsTask:Create'
            ],
            description: '...'
          }
        ]
      }
    ]
  },
  type: 'Exe',
  architecture: 'X86',
  publicKey: 'YDeX1TtGXVPwDjdGHrFBQJ7iIScZPaOyuCiDX+FtXGc=',
  broadcastKey: 'iPkmchE4hjJCDGYrbzGTai3WybLuZXsk/g3MUxi3ujw=',
  buildId: 'b1d0',
  commands: [
    {
      name: 'AddConnector',
      arguments: [
        {
          type: 'form',
          name: 'Connector type',
          defaultValue: [
            'connectors:TeamServer:Create',
            'connectors:MockServer:Create'
          ],
          description: '...'
        }
      ]
    },
    {
      name: 'AddChannel',
      arguments: [
        {
          type: 'form',
          name: 'Channel type',
          defaultValue: [
            'channels:NamedPipe:Create',
            'channels:EwsTask:Create'
          ],
          description: '...'
        }
      ]
    }
  ],
  peripherals: [
    {
      type: 0,
      name: 'Beacon',
      commands: [
        {
          name: 'Create',
          arguments: [
            {
              type: 'string',
              name: 'Pipe name',
              description: `Name of pipe that beacon opens. Name is encrypted in payload,
                'but is necessary for establishing communication`
            },
            {
              type: 'int16',
              min: 1,
              defaultValue: 10,
              name: 'Connection trials',
              description:
                'Connection tail may fail, which does not mean that whole staging was unsuccessful'
            },
            {
              type: 'int16',
              min: 1,
              defaultValue: 1000,
              name: 'Trials delay',
              description:
                'The time in milliseconds to wait between unsuccessful connection trails'
            },
            {
              type: 'base64',
              name: 'Payload',
              description: 'Payload with beacon to inject'
            }
          ]
        }
      ],
      description: '...'
    },
    {
      type: 1,
      name: 'Mock',
      commands: [
        {
          name: 'Create',
          arguments: []
        }
      ]
    }
  ],
  channels: [
    {
      type: 0,
      name: 'NamedPipe',
      commands: [
        {
          name: 'Create',
          arguments: [
            [
              {
                type: 'string',
                name: 'Input ID',
                min: 4,
                max: 4,
                randomize: true,
                description: 'Used to distinguish packets for the channel'
              },
              {
                type: 'string',
                name: 'Output ID',
                min: 4,
                max: 4,
                randomize: true,
                description: 'Used to distinguish packets from the channel'
              }
            ]
          ]
        }
      ]
    },
    {
      type: 1,
      name: 'EwsTask',
      commands: [
        {
          name: 'Create',
          arguments: [
            [
              {
                type: 'string',
                name: 'Input ID',
                min: 4,
                max: 4,
                randomize: true,
                description: 'Used to distinguish packets for the channel'
              },
              {
                type: 'string',
                name: 'Output ID',
                min: 4,
                max: 4,
                randomize: true,
                description: 'Used to distinguish packets from the channel'
              }
            ],
            {
              type: 'string',
              name: 'Uri',
              description: 'Uri of EWS server'
            },
            {
              type: 'string',
              name: 'Username',
              description: 'Username used to sign in'
            },
            {
              type: 'string',
              name: 'Password',
              description: 'Password used to sign in'
            },
            {
              type: 'boolean',
              name: 'Remove all task',
              defaultValue: true,
              description:
                'Clearing old tasks from server before starting communication may increase bandwidth'
            }
          ]
        },
        {
          name: 'RemoveAllTasks',
          arguments: []
        }
      ]
    }
  ]
};

export const commands = [
  {
    relayAgentId: 41425,
    id: 6,
    name: 'RelayCommand',
    data: {
      args: [
        {
          arg1: 'val1'
        }
      ],
      opt: 'optval'
    },
    isPending: true
  },
  {
    relayAgentId: 41425,
    interfaceId: 4561,
    id: 5,
    name: 'RelayInterfaceCommand',
    data: {
      args: [
        {
          arg1: 'val1'
        }
      ],
      opt: 'optval'
    },
    isPending: true
  },
  {
    interfaceId: 4561,
    id: 4,
    name: 'GatewayInterfaceCommand',
    data: {
      args: [
        {
          arg1: 'val1'
        }
      ],
      opt: 'optval'
    },
    isPending: true
  },
  {
    id: 3,
    name: 'GatewayCommand',
    data: {
      args: [
        {
          arg1: 'val1'
        }
      ],
      opt: 'optval'
    },
    isPending: true
  },
  {
    id: 1,
    name: 'GatewayCommand',
    data: {
      args: [
        {
          arg1: 'val1'
        }
      ],
      opt: 'optval'
    },
    isPending: true
  },
  {
    id: 0,
    name: 'GatewayCommand',
    data: {
      args: [
        {
          arg1: 'val1'
        }
      ],
      opt: 'optval'
    },
    isPending: true
  }
];
