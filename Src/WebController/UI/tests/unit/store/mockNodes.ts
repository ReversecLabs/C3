// tslint:disable max-line-length

import { C3Node, NodeKlass } from './../../../src/types/c3types';

export const nodes: C3Node[] = [
  {
    uid: '7c864a181f31cdba',
    klass: NodeKlass.Gateway,
    id: '7c864a181f31cdba',
    buildId: '1aa6',
    name: 'mock-gateway-1',
    pending: false,
    isActive: true,
    type: -1,
    error: null,
    parentId: null,
    parentKlass: null,
    timestamp: 1565270492
  },
  {
    uid: '1-7c864a181f31cdba',
    klass: NodeKlass.Channel,
    id: '1',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '7c864a181f31cdba',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Gateway,
    propertiesText: {
      arguments: [
        [
          {
            name: 'Input ID',
            type: 'string',
            value: 'h018'
          },
          {
            name: 'Output ID',
            type: 'string',
            value: '0znh'
          }
        ]
      ]
    }
  },
  {
    uid: '2-7c864a181f31cdba',
    klass: NodeKlass.Channel,
    id: '2',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '7c864a181f31cdba',
    isReturnChannel: false,
    isNegotiationChannel: true,
    parentKlass: NodeKlass.Gateway,
    propertiesText: {
      arguments: [
        {
          name: 'Negotiation Identifier',
          type: 'string',
          value: '65i9fkpj'
        }
      ]
    }
  },
  {
    uid: '3-7c864a181f31cdba',
    klass: NodeKlass.Channel,
    id: '3',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '7c864a181f31cdba',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Gateway,
    propertiesText: {
      arguments: [
        [
          {
            name: 'Input ID',
            type: 'string',
            value: 'a73hVxoy'
          },
          {
            name: 'Output ID',
            type: 'string',
            value: '48Fqe5Q7'
          }
        ]
      ]
    }
  },
  {
    uid: '4-7c864a181f31cdba',
    klass: NodeKlass.Channel,
    id: '4',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '7c864a181f31cdba',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Gateway,
    propertiesText: {
      arguments: [
        [
          {
            name: 'Input ID',
            type: 'string',
            value: 'SX4aqPpV'
          },
          {
            name: 'Output ID',
            type: 'string',
            value: 'ii4nQulM'
          }
        ]
      ]
    }
  },
  {
    uid: '95896bc3757517b0',
    klass: NodeKlass.Relay,
    id: '95896bc3757517b0',
    buildId: '1aa8',
    name: 'mock-relay-nego-X',
    pending: false,
    isActive: true,
    type: -1,
    error: null,
    parentId: '7c864a181f31cdba',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {}
  },
  {
    uid: '1-95896bc3757517b0',
    klass: NodeKlass.Channel,
    id: '1',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '95896bc3757517b0',
    isReturnChannel: false,
    isNegotiationChannel: true,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: [
        {
          name: 'Negotiation Identifier',
          type: 'string',
          value: '1evo5gkd'
        }
      ]
    }
  },
  {
    uid: '8000-95896bc3757517b0',
    klass: NodeKlass.Channel,
    id: '8000',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '95896bc3757517b0',
    isReturnChannel: true,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: null
    }
  },
  {
    uid: '8001-95896bc3757517b0',
    klass: NodeKlass.Channel,
    id: '8001',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '95896bc3757517b0',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: null
    }
  },
  {
    uid: '8002-95896bc3757517b0',
    klass: NodeKlass.Channel,
    id: '8002',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '95896bc3757517b0',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: null
    }
  },
  {
    uid: '8003-95896bc3757517b0',
    klass: NodeKlass.Channel,
    id: '8003',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '95896bc3757517b0',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: null
    }
  },
  {
    uid: 'aa0eaa3839d6d9c8',
    klass: NodeKlass.Relay,
    id: 'aa0eaa3839d6d9c8',
    buildId: '1aab',
    name: 'mock-relay-named-3',
    pending: false,
    isActive: true,
    type: -1,
    error: null,
    parentId: '7c864a181f31cdba',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {},
    timestamp: 1565270492
  },
  {
    uid: '0-aa0eaa3839d6d9c8',
    klass: NodeKlass.Channel,
    id: '0',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: 'aa0eaa3839d6d9c8',
    isReturnChannel: true,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: null
    }
  },
  {
    uid: '2-aa0eaa3839d6d9c8',
    klass: NodeKlass.Channel,
    id: '2',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: 'aa0eaa3839d6d9c8',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: [
        [
          {
            name: 'Input ID',
            type: 'string',
            value: 'kiv2'
          },
          {
            name: 'Output ID',
            type: 'string',
            value: '3vej'
          }
        ]
      ]
    }
  },
  {
    uid: 'c59e70f44dc584d7',
    klass: NodeKlass.Relay,
    id: 'c59e70f44dc584d7',
    buildId: '1aaa',
    name: 'mock-relay-nego-Z',
    pending: false,
    isActive: true,
    type: -1,
    error: null,
    parentId: '7c864a181f31cdba',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {}
  },
  {
    uid: '1-c59e70f44dc584d7',
    klass: NodeKlass.Channel,
    id: '1',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: 'c59e70f44dc584d7',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: [
        [
          {
            name: 'Input ID',
            type: 'string',
            value: 'bgzb'
          },
          {
            name: 'Output ID',
            type: 'string',
            value: '7sas'
          }
        ]
      ]
    }
  },
  {
    uid: '8000-c59e70f44dc584d7',
    klass: NodeKlass.Channel,
    id: '8000',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: 'c59e70f44dc584d7',
    isReturnChannel: true,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: null
    }
  },
  {
    uid: '4011a444def9464',
    klass: NodeKlass.Relay,
    id: '4011a444def9464',
    buildId: '1aa7',
    name: 'mock-relay-named-1',
    pending: false,
    isActive: true,
    type: -1,
    error: null,
    parentId: '7c864a181f31cdba',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {}
  },
  {
    uid: '0-4011a444def9464',
    klass: NodeKlass.Channel,
    id: '0',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '4011a444def9464',
    isReturnChannel: true,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: null
    }
  },
  {
    uid: '1-4011a444def9464',
    klass: NodeKlass.Channel,
    id: '1',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '4011a444def9464',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: [
        [
          {
            name: 'Input ID',
            type: 'string',
            value: 'd358'
          },
          {
            name: 'Output ID',
            type: 'string',
            value: '1hzt'
          }
        ]
      ]
    }
  },
  {
    uid: '2-4011a444def9464',
    klass: NodeKlass.Channel,
    id: '2',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '4011a444def9464',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: [
        [
          {
            name: 'Input ID',
            type: 'string',
            value: 'aaaa'
          },
          {
            name: 'Output ID',
            type: 'string',
            value: 'bbbb'
          }
        ]
      ]
    }
  },
  {
    uid: '3-4011a444def9464',
    klass: NodeKlass.Channel,
    id: '3',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '4011a444def9464',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: [
        [
          {
            name: 'Input ID',
            type: 'string',
            value: 'cccc'
          },
          {
            name: 'Output ID',
            type: 'string',
            value: 'dddd'
          }
        ]
      ]
    }
  },
  {
    uid: '36c0bcb85e82a447',
    klass: NodeKlass.Relay,
    id: '36c0bcb85e82a447',
    buildId: '1aaa',
    name: 'mock-relay-nego-Z',
    pending: false,
    isActive: true,
    type: -1,
    error: null,
    parentId: '7c864a181f31cdba',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {}
  },
  {
    uid: '8000-36c0bcb85e82a447',
    klass: NodeKlass.Channel,
    id: '8000',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '36c0bcb85e82a447',
    isReturnChannel: true,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: null
    }
  },
  {
    uid: '3a57b45b0273c52b',
    klass: NodeKlass.Relay,
    id: '3a57b45b0273c52b',
    buildId: '1aa8',
    name: 'mock-relay-nego-X',
    pending: false,
    isActive: true,
    type: -1,
    error: null,
    parentId: '7c864a181f31cdba',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {}
  },
  {
    uid: '1-3a57b45b0273c52b',
    klass: NodeKlass.Channel,
    id: '1',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '3a57b45b0273c52b',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: [
        [
          {
            name: 'Input ID',
            type: 'string',
            value: 'gggg'
          },
          {
            name: 'Output ID',
            type: 'string',
            value: 'hhhh'
          }
        ]
      ]
    }
  },
  {
    uid: '8000-3a57b45b0273c52b',
    klass: NodeKlass.Channel,
    id: '8000',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '3a57b45b0273c52b',
    isReturnChannel: true,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: null
    }
  },
  {
    uid: '68035347127c17dc',
    klass: NodeKlass.Relay,
    id: '68035347127c17dc',
    buildId: '1aa9',
    name: 'mock-relay-named-2',
    pending: false,
    isActive: true,
    type: -1,
    error: null,
    parentId: '7c864a181f31cdba',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {}
  },
  {
    uid: '0-68035347127c17dc',
    klass: NodeKlass.Channel,
    id: '0',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '68035347127c17dc',
    isReturnChannel: true,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: null
    }
  },
  {
    uid: '1-68035347127c17dc',
    klass: NodeKlass.Channel,
    id: '1',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '68035347127c17dc',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: [
        [
          {
            name: 'Input ID',
            type: 'string',
            value: 'eeee'
          },
          {
            name: 'Output ID',
            type: 'string',
            value: 'ffff'
          }
        ]
      ]
    }
  },
  {
    uid: '6f06a07c9263d0cb',
    klass: NodeKlass.Relay,
    id: '6f06a07c9263d0cb',
    buildId: '1aaa',
    name: 'mock-relay-nego-Z',
    pending: false,
    isActive: true,
    type: -1,
    error: null,
    parentId: '7c864a181f31cdba',
    parentKlass: NodeKlass.Gateway,
    initialCommand: {}
  },
  {
    uid: '1-6f06a07c9263d0cb',
    klass: NodeKlass.Channel,
    id: '1',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '6f06a07c9263d0cb',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: [
        [
          {
            name: 'Input ID',
            type: 'string',
            value: '7q5b'
          },
          {
            name: 'Output ID',
            type: 'string',
            value: 'l7wf'
          }
        ]
      ]
    }
  },
  {
    uid: '2-6f06a07c9263d0cb',
    klass: NodeKlass.Channel,
    id: '2',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '6f06a07c9263d0cb',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: [
        [
          {
            name: 'Input ID',
            type: 'string',
            value: 'n3ca'
          },
          {
            name: 'Output ID',
            type: 'string',
            value: 'dsvz'
          }
        ]
      ]
    }
  },
  {
    uid: '3-6f06a07c9263d0cb',
    klass: NodeKlass.Channel,
    id: '3',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '6f06a07c9263d0cb',
    isReturnChannel: false,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: [
        [
          {
            name: 'Input ID',
            type: 'string',
            value: 'ctvg'
          },
          {
            name: 'Output ID',
            type: 'string',
            value: 'idck'
          }
        ]
      ]
    }
  },
  {
    uid: '8000-6f06a07c9263d0cb',
    klass: NodeKlass.Channel,
    id: '8000',
    pending: false,
    type: 3583579335,
    error: null,
    parentId: '6f06a07c9263d0cb',
    isReturnChannel: true,
    isNegotiationChannel: false,
    parentKlass: NodeKlass.Relay,
    propertiesText: {
      arguments: null
    }
  }
];
