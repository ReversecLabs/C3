// tslint:disable max-line-length

export const gateway = [
  {
    relays: [
      {
        agentId: '95896bc3757517b0',
        buildId: '1aa8',
        name: 'mock-relay-nego-X',
        channels: [
          {
            iid: '1',
            type: 3583579335,
            isNegotiationChannel: true,
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
            iid: '8000',
            type: 3583579335,
            isReturnChannel: true,
            propertiesText: {
              arguments: null
            }
          },
          {
            iid: '8001',
            type: 3583579335,
            propertiesText: {
              arguments: null
            }
          },
          {
            iid: '8002',
            type: 3583579335,
            propertiesText: {
              arguments: null
            }
          },
          {
            iid: '8003',
            type: 3583579335,
            propertiesText: {
              arguments: null
            }
          }
        ],
        peripherals: [],
        routes: [
          {
            outgoingInterface: '8001',
            destinationAgent: '36c0bcb85e82a447',
            receivingInterface: '8000',
            isNeighbour: true
          },
          {
            outgoingInterface: '8002',
            destinationAgent: 'aa0eaa3839d6d9c8',
            receivingInterface: '0'
          },
          {
            outgoingInterface: '8002',
            destinationAgent: 'c59e70f44dc584d7',
            receivingInterface: '8000',
            isNeighbour: true
          },
          {
            outgoingInterface: '8003',
            destinationAgent: '6f06a07c9263d0cb',
            receivingInterface: '8000',
            isNeighbour: true
          }
        ],
        isActive: true
      },
      {
        agentId: 'aa0eaa3839d6d9c8',
        buildId: '1aab',
        name: 'mock-relay-named-3',
        channels: [
          {
            iid: '0',
            type: 3583579335,
            isReturnChannel: true,
            propertiesText: {
              arguments: null
            }
          },
          {
            iid: '2',
            type: 3583579335,
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
          }
        ],
        peripherals: [],
        routes: [],
        isActive: true
      },
      {
        agentId: 'c59e70f44dc584d7',
        buildId: '1aaa',
        name: 'mock-relay-nego-Z',
        channels: [
          {
            iid: '1',
            type: 3583579335,
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
            iid: '8000',
            type: 3583579335,
            isReturnChannel: true,
            propertiesText: {
              arguments: null
            }
          }
        ],
        peripherals: [],
        routes: [
          {
            outgoingInterface: '1',
            destinationAgent: 'aa0eaa3839d6d9c8',
            receivingInterface: '0',
            isNeighbour: true
          }
        ],
        isActive: true
      },
      {
        agentId: '4011a444def9464',
        buildId: '1aa7',
        name: 'mock-relay-named-1',
        channels: [
          {
            iid: '0',
            type: 3583579335,
            isReturnChannel: true,
            propertiesText: {
              arguments: null
            }
          },
          {
            iid: '1',
            type: 3583579335,
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
            iid: '2',
            type: 3583579335,
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
            iid: '3',
            type: 3583579335,
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
          }
        ],
        peripherals: [],
        routes: [
          {
            outgoingInterface: '1',
            destinationAgent: '68035347127c17dc',
            receivingInterface: '0',
            isNeighbour: true
          }
        ],
        isActive: true
      },
      {
        agentId: '36c0bcb85e82a447',
        buildId: '1aaa',
        name: 'mock-relay-nego-Z',
        channels: [
          {
            iid: '8000',
            type: 3583579335,
            isReturnChannel: true,
            propertiesText: {
              arguments: null
            }
          }
        ],
        peripherals: [],
        routes: [],
        isActive: true
      },
      {
        agentId: '3a57b45b0273c52b',
        buildId: '1aa8',
        name: 'mock-relay-nego-X',
        channels: [
          {
            iid: '1',
            type: 3583579335,
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
            iid: '8000',
            type: 3583579335,
            isReturnChannel: true,
            propertiesText: {
              arguments: null
            }
          }
        ],
        peripherals: [],
        routes: [],
        isActive: true
      },
      {
        agentId: '68035347127c17dc',
        buildId: '1aa9',
        name: 'mock-relay-named-2',
        channels: [
          {
            iid: '0',
            type: 3583579335,
            isReturnChannel: true,
            propertiesText: {
              arguments: null
            }
          },
          {
            iid: '1',
            type: 3583579335,
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
          }
        ],
        peripherals: [],
        routes: [],
        isActive: true
      },
      {
        agentId: '6f06a07c9263d0cb',
        buildId: '1aaa',
        name: 'mock-relay-nego-Z',
        channels: [
          {
            iid: '1',
            type: 3583579335,
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
            iid: '2',
            type: 3583579335,
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
            iid: '3',
            type: 3583579335,
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
            iid: '8000',
            type: 3583579335,
            isReturnChannel: true,
            propertiesText: {
              arguments: null
            }
          }
        ],
        peripherals: [],
        routes: [],
        isActive: true
      }
    ],
    connectors: [],
    agentId: '7c864a181f31cdba',
    buildId: '1aa6',
    name: 'mock-gateway-1',
    channels: [
      {
        iid: '1',
        type: 3583579335,
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
        iid: '2',
        type: 3583579335,
        isNegotiationChannel: true,
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
        iid: '3',
        type: 3583579335,
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
        iid: '4',
        type: 3583579335,
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
      }
    ],
    peripherals: [],
    routes: [
      {
        outgoingInterface: '1',
        destinationAgent: '4011a444def9464',
        receivingInterface: '0',
        isNeighbour: true
      },
      {
        outgoingInterface: '1',
        destinationAgent: '68035347127c17dc',
        receivingInterface: '0'
      },
      {
        outgoingInterface: '3',
        destinationAgent: '95896bc3757517b0',
        receivingInterface: '8000',
        isNeighbour: true
      },
      {
        outgoingInterface: '3',
        destinationAgent: 'aa0eaa3839d6d9c8',
        receivingInterface: '0'
      },
      {
        outgoingInterface: '3',
        destinationAgent: 'c59e70f44dc584d7',
        receivingInterface: '8000'
      },
      {
        outgoingInterface: '3',
        destinationAgent: '36c0bcb85e82a447',
        receivingInterface: '8000'
      },
      {
        outgoingInterface: '3',
        destinationAgent: '6f06a07c9263d0cb',
        receivingInterface: '8000'
      },
      {
        outgoingInterface: '4',
        destinationAgent: '3a57b45b0273c52b',
        receivingInterface: '8000',
        isNeighbour: true
      }
    ],
    isActive: true
  }
];
