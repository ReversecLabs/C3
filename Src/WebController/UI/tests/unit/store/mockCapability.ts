// tslint:disable max-line-length

export const capability = {
  buildId: '1aa6',
  commands: [
    {
      name: 'GatewayCommandGroup',
      arguments: [
        {
          type: 'form',
          name: 'Gateway',
          defaultValue: [
            'gateway:Command:Close',
            'gateway:Command:CreateRoute',
            'gateway:Command:RemoveRoute',
            'gateway:Command:TurnOnConnectorMockServer',
            'gateway:Command:TurnOnConnectorTeamServer',
            'gateway:Command:AddPeripheralMock',
            'gateway:Command:AddPeripheralBeacon',
            'gateway:Command:AddChannelEwsTask',
            'gateway:Command:AddNegotiationChannelEwsTask',
            'gateway:Command:AddChannelContributionTestChannel',
            'gateway:Command:AddNegotiationChannelContributionTestChannel',
            'gateway:Command:AddChannelOneDrive365RestFile',
            'gateway:Command:AddNegotiationChannelOneDrive365RestFile',
            'gateway:Command:AddChannelNamedPipe',
            'gateway:Command:AddNegotiationChannelNamedPipe',
            'gateway:Command:AddChannelOutlook365RestTask',
            'gateway:Command:AddNegotiationChannelOutlook365RestTask',
            'gateway:Command:AddChannelSlack',
            'gateway:Command:AddNegotiationChannelSlack',
            'gateway:Command:AddChannelUncShareFile',
            'gateway:Command:AddNegotiationChannelUncShareFile'
          ]
        }
      ]
    }
  ],
  peripherals: [
    {
      commands: [
        {
          arguments: [
            {
              description:
                'Error set on connector. Send empty to clean up error',
              name: 'Error message'
            }
          ],
          description: 'Set error on connector.',
          id: 0,
          name: 'Test command'
        },
        {
          arguments: [],
          id: 65535,
          name: 'Close'
        },
        {
          arguments: [
            {
              description: 'Minimal delay in milliseconds',
              min: 30,
              name: 'Min',
              type: 'uint16'
            },
            {
              description: 'Maximal delay in milliseconds. ',
              min: 30,
              name: 'Max',
              type: 'uint16'
            }
          ],
          description: 'Set delay between receiving function calls.',
          id: 65534,
          name: 'UpdateDelayJitter'
        }
      ],
      name: 'Mock',
      type: 1562929860
    },
    {
      commands: [
        {
          arguments: [],
          id: 65535,
          name: 'Close'
        },
        {
          arguments: [
            {
              description: 'Minimal delay in milliseconds',
              min: 30,
              name: 'Min',
              type: 'uint16'
            },
            {
              description: 'Maximal delay in milliseconds. ',
              min: 30,
              name: 'Max',
              type: 'uint16'
            }
          ],
          description: 'Set delay between receiving function calls.',
          id: 65534,
          name: 'UpdateDelayJitter'
        }
      ],
      name: 'Beacon',
      type: 2927991403
    }
  ],
  channels: [
    {
      commands: [
        {
          arguments: [],
          description: 'Clearing old tasks from server may increase bandwidth',
          id: 0,
          name: 'Remove all tasks'
        },
        {
          arguments: [],
          id: 65535,
          name: 'Close'
        },
        {
          arguments: [
            {
              description: 'Minimal delay in milliseconds',
              min: 30,
              name: 'Min',
              type: 'uint16'
            },
            {
              description: 'Maximal delay in milliseconds. ',
              min: 30,
              name: 'Max',
              type: 'uint16'
            }
          ],
          description: 'Set delay between receiving function calls.',
          id: 65534,
          name: 'UpdateDelayJitter'
        },
        {
          name: 'Create',
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description: 'Uri of EWS server',
              min: 1,
              name: 'Uri',
              type: 'string'
            },
            {
              description: 'Username used to sign in',
              min: 1,
              name: 'Username',
              type: 'string'
            },
            {
              description: 'Password used to sign in',
              name: 'Password',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old tasks from server before starting communication may increase bandwidth',
              name: 'Remove all task',
              type: 'boolean'
            }
          ]
        }
      ],
      name: 'EwsTask',
      type: 3521084197
    },
    {
      commands: [
        {
          arguments: [
            {
              description:
                'Error set on connector. Send empty to clean up error',
              name: 'Error message'
            }
          ],
          description: 'Set error on connector.',
          id: 0,
          name: 'Test command'
        },
        {
          arguments: [],
          id: 65535,
          name: 'Close'
        },
        {
          arguments: [
            {
              description: 'Minimal delay in milliseconds',
              min: 30,
              name: 'Min',
              type: 'uint16'
            },
            {
              description: 'Maximal delay in milliseconds. ',
              min: 30,
              name: 'Max',
              type: 'uint16'
            }
          ],
          description: 'Set delay between receiving function calls.',
          id: 65534,
          name: 'UpdateDelayJitter'
        },
        {
          name: 'Create',
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ]
          ]
        }
      ],
      name: 'ContributionTestChannel',
      type: 2865778679
    },
    {
      commands: [
        {
          arguments: [],
          description: 'Clearing old files from server may increase bandwidth',
          id: 0,
          name: 'Remove all files'
        },
        {
          arguments: [],
          id: 65535,
          name: 'Close'
        },
        {
          arguments: [
            {
              description: 'Minimal delay in milliseconds',
              min: 30,
              name: 'Min',
              type: 'uint16'
            },
            {
              description: 'Maximal delay in milliseconds. ',
              min: 30,
              name: 'Max',
              type: 'uint16'
            }
          ],
          description: 'Set delay between receiving function calls.',
          id: 65534,
          name: 'UpdateDelayJitter'
        },
        {
          name: 'Create',
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description:
                'Refresh token manually generated for an application',
              min: 1,
              name: 'Refresh token',
              type: 'string'
            },
            {
              description: 'Identifies the application (e.g. a GUID)',
              min: 1,
              name: 'Client key',
              type: 'string'
            },
            {
              description:
                'Used for authentication for the application (e.g. a password)',
              min: 1,
              name: 'Client secret',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old files from server before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ]
        }
      ],
      name: 'OneDrive365RestFile',
      type: 3235357973
    },
    {
      commands: [
        {
          arguments: [],
          id: 65535,
          name: 'Close'
        },
        {
          arguments: [
            {
              description: 'Minimal delay in milliseconds',
              min: 30,
              name: 'Min',
              type: 'uint16'
            },
            {
              description: 'Maximal delay in milliseconds. ',
              min: 30,
              name: 'Max',
              type: 'uint16'
            }
          ],
          description: 'Set delay between receiving function calls.',
          id: 65534,
          name: 'UpdateDelayJitter'
        },
        {
          name: 'Create',
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ]
          ]
        }
      ],
      name: 'NamedPipe',
      type: 3583579335
    },
    {
      commands: [
        {
          arguments: [],
          description: 'Clearing old tasks from server may increase bandwidth',
          id: 0,
          name: 'Remove all tasks'
        },
        {
          arguments: [],
          id: 65535,
          name: 'Close'
        },
        {
          arguments: [
            {
              description: 'Minimal delay in milliseconds',
              min: 30,
              name: 'Min',
              type: 'uint16'
            },
            {
              description: 'Maximal delay in milliseconds. ',
              min: 30,
              name: 'Max',
              type: 'uint16'
            }
          ],
          description: 'Set delay between receiving function calls.',
          id: 65534,
          name: 'UpdateDelayJitter'
        },
        {
          name: 'Create',
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description:
                'Refresh token manually generated for an application',
              min: 1,
              name: 'Refresh token',
              type: 'string'
            },
            {
              description: 'Identifies the application (e.g. a GUID)',
              min: 1,
              name: 'Client key',
              type: 'string'
            },
            {
              description:
                'Used for authentication for the application (e.g. a password)',
              min: 1,
              name: 'Client secret',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old tasks from server before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ]
        }
      ],
      name: 'Outlook365RestTask',
      type: 1387616683
    },
    {
      commands: [
        {
          arguments: [],
          id: 65535,
          name: 'Close'
        },
        {
          arguments: [
            {
              description: 'Minimal delay in milliseconds',
              min: 30,
              name: 'Min',
              type: 'uint16'
            },
            {
              description: 'Maximal delay in milliseconds. ',
              min: 30,
              name: 'Max',
              type: 'uint16'
            }
          ],
          description: 'Set delay between receiving function calls.',
          id: 65534,
          name: 'UpdateDelayJitter'
        },
        {
          name: 'Create',
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description:
                "This token is what channel needs to interact with Slack's API",
              min: 1,
              name: 'Slack token',
              type: 'string'
            },
            {
              description: "Name of Slack's channel used by api",
              min: 4,
              name: 'Channel name',
              randomize: true,
              type: 'string'
            }
          ]
        }
      ],
      name: 'Slack',
      type: 761093896
    },
    {
      commands: [
        {
          arguments: [],
          description:
            'Clearing old files from directory may increase bandwidth',
          id: 0,
          name: 'Remove all message files'
        },
        {
          arguments: [],
          id: 65535,
          name: 'Close'
        },
        {
          arguments: [
            {
              description: 'Minimal delay in milliseconds',
              min: 30,
              name: 'Min',
              type: 'uint16'
            },
            {
              description: 'Maximal delay in milliseconds. ',
              min: 30,
              name: 'Max',
              type: 'uint16'
            }
          ],
          description: 'Set delay between receiving function calls.',
          id: 65534,
          name: 'UpdateDelayJitter'
        },
        {
          name: 'Create',
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description: 'UNC or absolute path of fileshare',
              min: 1,
              name: 'Filesystem path',
              type: 'string'
            },
            {
              defaultValue: false,
              description:
                'Clearing old files before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ]
        }
      ],
      name: 'UncShareFile',
      type: 2164756926
    }
  ],
  connectors: [
    {
      commands: [
        {
          arguments: [
            {
              description:
                'Error set on connector. Send empty to clean up error',
              name: 'Error message'
            }
          ],
          description: 'Set error on connector.',
          id: 0,
          name: 'Test command'
        },
        {
          arguments: [],
          id: 65535,
          name: 'TurnOff'
        }
      ],
      name: 'MockServer',
      type: 2331856458
    },
    {
      commands: [
        {
          arguments: [
            {
              description: 'Id associated to beacon',
              min: 1,
              name: 'Route Id'
            }
          ],
          description:
            'Close socket connection with TeamServer if beacon is not available',
          id: 1,
          name: 'Close connection'
        },
        {
          arguments: [],
          id: 65535,
          name: 'TurnOff'
        }
      ],
      name: 'TeamServer',
      type: 549339708
    }
  ],
  relayCommands: {
    commands: [
      {
        name: 'RelayCommandGroup',
        arguments: [
          {
            type: 'form',
            name: 'Relay',
            defaultValue: [
              'relay:Command:Close',
              'relay:Command:CreateRoute',
              'relay:Command:RemoveRoute',
              'relay:Command:AddPeripheralMock',
              'relay:Command:AddPeripheralBeacon',
              'relay:Command:AddChannelEwsTask',
              'relay:Command:AddNegotiationChannelEwsTask',
              'relay:Command:AddChannelContributionTestChannel',
              'relay:Command:AddNegotiationChannelContributionTestChannel',
              'relay:Command:AddChannelOneDrive365RestFile',
              'relay:Command:AddNegotiationChannelOneDrive365RestFile',
              'relay:Command:AddChannelNamedPipe',
              'relay:Command:AddNegotiationChannelNamedPipe',
              'relay:Command:AddChannelOutlook365RestTask',
              'relay:Command:AddNegotiationChannelOutlook365RestTask',
              'relay:Command:AddChannelSlack',
              'relay:Command:AddNegotiationChannelSlack',
              'relay:Command:AddChannelUncShareFile',
              'relay:Command:AddNegotiationChannelUncShareFile'
            ]
          }
        ]
      }
    ]
  },
  gateway: [
    {
      name: 'Command',
      type: 0,
      commands: [
        {
          arguments: [],
          id: 65535,
          name: 'Close'
        },
        {
          arguments: [
            {
              description: 'Id of route in string form.',
              min: 1,
              name: 'RouteID',
              type: 'string'
            },
            {
              description: 'Id of device in string form.',
              min: 1,
              name: 'DeviceId',
              type: 'string'
            },
            {
              defaultValue: true,
              description: 'Informs if relay is direct neighbour.',
              name: 'Neighbour',
              type: 'boolean'
            }
          ],
          id: 65533,
          name: 'CreateRoute'
        },
        {
          arguments: [
            {
              description: 'Id of route in string form.',
              min: 1,
              name: 'RouteID',
              type: 'string'
            }
          ],
          id: 65532,
          name: 'RemoveRoute'
        },
        {
          arguments: [],
          id: 65279,
          name: 'TurnOnConnectorMockServer'
        },
        {
          arguments: [
            {
              description: 'Listening post address',
              name: 'Address',
              type: 'ip'
            },
            {
              description: 'Listening post port',
              min: 1,
              name: 'Port',
              type: 'uint16'
            }
          ],
          id: 65278,
          name: 'TurnOnConnectorTeamServer'
        },
        {
          arguments: [],
          id: 65277,
          name: 'AddPeripheralMock'
        },
        {
          arguments: [
            {
              description: 'Name of the pipe Beacon uses for communication.',
              min: 4,
              name: 'Pipe name',
              randomize: true,
              type: 'string'
            },
            {
              defaultValue: 10,
              description:
                'Number of connection trials before marking whole staging process unsuccessful.',
              min: 1,
              name: 'Connection trials',
              type: 'int16'
            },
            {
              defaultValue: 1000,
              description:
                'Time in milliseconds to wait between unsuccessful connection trails.',
              min: 30,
              name: 'Trials delay',
              type: 'int16'
            },
            {
              description:
                'Implant to inject. Leave empty to generate payload. BETA: Always leave empty, custom payload will not work.',
              name: 'Payload',
              type: 'binary'
            }
          ],
          id: 65276,
          name: 'AddPeripheralBeacon'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description: 'Uri of EWS server',
              min: 1,
              name: 'Uri',
              type: 'string'
            },
            {
              description: 'Username used to sign in',
              min: 1,
              name: 'Username',
              type: 'string'
            },
            {
              description: 'Password used to sign in',
              name: 'Password',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old tasks from server before starting communication may increase bandwidth',
              name: 'Remove all task',
              type: 'boolean'
            }
          ],
          id: 65275,
          name: 'AddChannelEwsTask'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            },
            {
              description: 'Uri of EWS server',
              min: 1,
              name: 'Uri',
              type: 'string'
            },
            {
              description: 'Username used to sign in',
              min: 1,
              name: 'Username',
              type: 'string'
            },
            {
              description: 'Password used to sign in',
              name: 'Password',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old tasks from server before starting communication may increase bandwidth',
              name: 'Remove all task',
              type: 'boolean'
            }
          ],
          id: 65274,
          name: 'AddNegotiationChannelEwsTask'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ]
          ],
          id: 65273,
          name: 'AddChannelContributionTestChannel'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            }
          ],
          id: 65272,
          name: 'AddNegotiationChannelContributionTestChannel'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description:
                'Refresh token manually generated for an application',
              min: 1,
              name: 'Refresh token',
              type: 'string'
            },
            {
              description: 'Identifies the application (e.g. a GUID)',
              min: 1,
              name: 'Client key',
              type: 'string'
            },
            {
              description:
                'Used for authentication for the application (e.g. a password)',
              min: 1,
              name: 'Client secret',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old files from server before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ],
          id: 65271,
          name: 'AddChannelOneDrive365RestFile'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            },
            {
              description:
                'Refresh token manually generated for an application',
              min: 1,
              name: 'Refresh token',
              type: 'string'
            },
            {
              description: 'Identifies the application (e.g. a GUID)',
              min: 1,
              name: 'Client key',
              type: 'string'
            },
            {
              description:
                'Used for authentication for the application (e.g. a password)',
              min: 1,
              name: 'Client secret',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old files from server before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ],
          id: 65270,
          name: 'AddNegotiationChannelOneDrive365RestFile'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ]
          ],
          id: 65269,
          name: 'AddChannelNamedPipe'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            }
          ],
          id: 65268,
          name: 'AddNegotiationChannelNamedPipe'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description:
                'Refresh token manually generated for an application',
              min: 1,
              name: 'Refresh token',
              type: 'string'
            },
            {
              description: 'Identifies the application (e.g. a GUID)',
              min: 1,
              name: 'Client key',
              type: 'string'
            },
            {
              description:
                'Used for authentication for the application (e.g. a password)',
              min: 1,
              name: 'Client secret',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old tasks from server before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ],
          id: 65267,
          name: 'AddChannelOutlook365RestTask'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            },
            {
              description:
                'Refresh token manually generated for an application',
              min: 1,
              name: 'Refresh token',
              type: 'string'
            },
            {
              description: 'Identifies the application (e.g. a GUID)',
              min: 1,
              name: 'Client key',
              type: 'string'
            },
            {
              description:
                'Used for authentication for the application (e.g. a password)',
              min: 1,
              name: 'Client secret',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old tasks from server before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ],
          id: 65266,
          name: 'AddNegotiationChannelOutlook365RestTask'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description:
                "This token is what channel needs to interact with Slack's API",
              min: 1,
              name: 'Slack token',
              type: 'string'
            },
            {
              description: "Name of Slack's channel used by api",
              min: 4,
              name: 'Channel name',
              randomize: true,
              type: 'string'
            }
          ],
          id: 65265,
          name: 'AddChannelSlack'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            },
            {
              description:
                "This token is what channel needs to interact with Slack's API",
              min: 1,
              name: 'Slack token',
              type: 'string'
            },
            {
              description: "Name of Slack's channel used by api",
              min: 4,
              name: 'Channel name',
              randomize: true,
              type: 'string'
            }
          ],
          id: 65264,
          name: 'AddNegotiationChannelSlack'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description: 'UNC or absolute path of fileshare',
              min: 1,
              name: 'Filesystem path',
              type: 'string'
            },
            {
              defaultValue: false,
              description:
                'Clearing old files before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ],
          id: 65263,
          name: 'AddChannelUncShareFile'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            },
            {
              description: 'UNC or absolute path of fileshare',
              min: 1,
              name: 'Filesystem path',
              type: 'string'
            },
            {
              defaultValue: false,
              description:
                'Clearing old files before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ],
          id: 65262,
          name: 'AddNegotiationChannelUncShareFile'
        }
      ]
    }
  ],
  relay: [
    {
      name: 'Command',
      type: 0,
      commands: [
        {
          arguments: [],
          id: 65535,
          name: 'Close'
        },
        {
          arguments: [
            {
              description: 'Id of route in string form.',
              min: 1,
              name: 'RouteID',
              type: 'string'
            },
            {
              description: 'Id of device in string form.',
              min: 1,
              name: 'DeviceId',
              type: 'string'
            },
            {
              defaultValue: true,
              description: 'Informs if relay is direct neighbour.',
              name: 'Neighbour',
              type: 'boolean'
            }
          ],
          id: 65533,
          name: 'CreateRoute'
        },
        {
          arguments: [
            {
              description: 'Id of route in string form.',
              min: 1,
              name: 'RouteID',
              type: 'string'
            }
          ],
          id: 65532,
          name: 'RemoveRoute'
        },
        {
          arguments: [],
          id: 65277,
          name: 'AddPeripheralMock'
        },
        {
          arguments: [
            {
              description: 'Name of the pipe Beacon uses for communication.',
              min: 4,
              name: 'Pipe name',
              randomize: true,
              type: 'string'
            },
            {
              defaultValue: 10,
              description:
                'Number of connection trials before marking whole staging process unsuccessful.',
              min: 1,
              name: 'Connection trials',
              type: 'int16'
            },
            {
              defaultValue: 1000,
              description:
                'Time in milliseconds to wait between unsuccessful connection trails.',
              min: 30,
              name: 'Trials delay',
              type: 'int16'
            },
            {
              description:
                'Implant to inject. Leave empty to generate payload. BETA: Always leave empty, custom payload will not work.',
              name: 'Payload',
              type: 'binary'
            }
          ],
          id: 65276,
          name: 'AddPeripheralBeacon'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description: 'Uri of EWS server',
              min: 1,
              name: 'Uri',
              type: 'string'
            },
            {
              description: 'Username used to sign in',
              min: 1,
              name: 'Username',
              type: 'string'
            },
            {
              description: 'Password used to sign in',
              name: 'Password',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old tasks from server before starting communication may increase bandwidth',
              name: 'Remove all task',
              type: 'boolean'
            }
          ],
          id: 65275,
          name: 'AddChannelEwsTask'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            },
            {
              description: 'Uri of EWS server',
              min: 1,
              name: 'Uri',
              type: 'string'
            },
            {
              description: 'Username used to sign in',
              min: 1,
              name: 'Username',
              type: 'string'
            },
            {
              description: 'Password used to sign in',
              name: 'Password',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old tasks from server before starting communication may increase bandwidth',
              name: 'Remove all task',
              type: 'boolean'
            }
          ],
          id: 65274,
          name: 'AddNegotiationChannelEwsTask'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ]
          ],
          id: 65273,
          name: 'AddChannelContributionTestChannel'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            }
          ],
          id: 65272,
          name: 'AddNegotiationChannelContributionTestChannel'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description:
                'Refresh token manually generated for an application',
              min: 1,
              name: 'Refresh token',
              type: 'string'
            },
            {
              description: 'Identifies the application (e.g. a GUID)',
              min: 1,
              name: 'Client key',
              type: 'string'
            },
            {
              description:
                'Used for authentication for the application (e.g. a password)',
              min: 1,
              name: 'Client secret',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old files from server before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ],
          id: 65271,
          name: 'AddChannelOneDrive365RestFile'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            },
            {
              description:
                'Refresh token manually generated for an application',
              min: 1,
              name: 'Refresh token',
              type: 'string'
            },
            {
              description: 'Identifies the application (e.g. a GUID)',
              min: 1,
              name: 'Client key',
              type: 'string'
            },
            {
              description:
                'Used for authentication for the application (e.g. a password)',
              min: 1,
              name: 'Client secret',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old files from server before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ],
          id: 65270,
          name: 'AddNegotiationChannelOneDrive365RestFile'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ]
          ],
          id: 65269,
          name: 'AddChannelNamedPipe'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            }
          ],
          id: 65268,
          name: 'AddNegotiationChannelNamedPipe'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description:
                'Refresh token manually generated for an application',
              min: 1,
              name: 'Refresh token',
              type: 'string'
            },
            {
              description: 'Identifies the application (e.g. a GUID)',
              min: 1,
              name: 'Client key',
              type: 'string'
            },
            {
              description:
                'Used for authentication for the application (e.g. a password)',
              min: 1,
              name: 'Client secret',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old tasks from server before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ],
          id: 65267,
          name: 'AddChannelOutlook365RestTask'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            },
            {
              description:
                'Refresh token manually generated for an application',
              min: 1,
              name: 'Refresh token',
              type: 'string'
            },
            {
              description: 'Identifies the application (e.g. a GUID)',
              min: 1,
              name: 'Client key',
              type: 'string'
            },
            {
              description:
                'Used for authentication for the application (e.g. a password)',
              min: 1,
              name: 'Client secret',
              type: 'string'
            },
            {
              defaultValue: true,
              description:
                'Clearing old tasks from server before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ],
          id: 65266,
          name: 'AddNegotiationChannelOutlook365RestTask'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description:
                "This token is what channel needs to interact with Slack's API",
              min: 1,
              name: 'Slack token',
              type: 'string'
            },
            {
              description: "Name of Slack's channel used by api",
              min: 4,
              name: 'Channel name',
              randomize: true,
              type: 'string'
            }
          ],
          id: 65265,
          name: 'AddChannelSlack'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            },
            {
              description:
                "This token is what channel needs to interact with Slack's API",
              min: 1,
              name: 'Slack token',
              type: 'string'
            },
            {
              description: "Name of Slack's channel used by api",
              min: 4,
              name: 'Channel name',
              randomize: true,
              type: 'string'
            }
          ],
          id: 65264,
          name: 'AddNegotiationChannelSlack'
        },
        {
          arguments: [
            [
              {
                description: 'Used to distinguish packets for the channel',
                min: 4,
                name: 'Input ID',
                randomize: true,
                type: 'string'
              },
              {
                description: 'Used to distinguish packets from the channel',
                min: 4,
                name: 'Output ID',
                randomize: true,
                type: 'string'
              }
            ],
            {
              description: 'UNC or absolute path of fileshare',
              min: 1,
              name: 'Filesystem path',
              type: 'string'
            },
            {
              defaultValue: false,
              description:
                'Clearing old files before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ],
          id: 65263,
          name: 'AddChannelUncShareFile'
        },
        {
          arguments: [
            {
              description:
                'One identifier used to negotiate identifiers for each joining relay',
              name: 'Negotiation Identifier',
              randomize: true,
              type: 'string'
            },
            {
              description: 'UNC or absolute path of fileshare',
              min: 1,
              name: 'Filesystem path',
              type: 'string'
            },
            {
              defaultValue: false,
              description:
                'Clearing old files before starting communication may increase bandwidth',
              name: 'Clear',
              type: 'boolean'
            }
          ],
          id: 65262,
          name: 'AddNegotiationChannelUncShareFile'
        }
      ]
    }
  ],
  channelCommands: {
    commands: [
      {
        name: 'ChannelCommandGroup',
        arguments: [
          {
            type: 'form',
            name: 'Channel',
            defaultValue: [
              'channels:EwsTask:Remove all tasks',
              'channels:EwsTask:Close',
              'channels:EwsTask:UpdateDelayJitter',
              'channels:ContributionTestChannel:Test command',
              'channels:ContributionTestChannel:Close',
              'channels:ContributionTestChannel:UpdateDelayJitter',
              'channels:OneDrive365RestFile:Remove all files',
              'channels:OneDrive365RestFile:Close',
              'channels:OneDrive365RestFile:UpdateDelayJitter',
              'channels:NamedPipe:Close',
              'channels:NamedPipe:UpdateDelayJitter',
              'channels:Outlook365RestTask:Remove all tasks',
              'channels:Outlook365RestTask:Close',
              'channels:Outlook365RestTask:UpdateDelayJitter',
              'channels:Slack:Close',
              'channels:Slack:UpdateDelayJitter',
              'channels:UncShareFile:Remove all message files',
              'channels:UncShareFile:Close',
              'channels:UncShareFile:UpdateDelayJitter'
            ]
          }
        ]
      }
    ]
  },
  connectorCommands: {
    commands: [
      {
        name: 'PeripheralCommandGroup',
        arguments: [
          {
            type: 'form',
            name: 'Peripheral',
            defaultValue: [
              'connectors:MockServer:Test command',
              'connectors:MockServer:TurnOff',
              'connectors:TeamServer:Close connection',
              'connectors:TeamServer:TurnOff'
            ]
          }
        ]
      }
    ]
  },
  peripheralCommands: {
    commands: [
      {
        name: 'PeripheralCommandGroup',
        arguments: [
          {
            type: 'form',
            name: 'Peripheral',
            defaultValue: [
              'peripherals:Mock:Test command',
              'peripherals:Mock:Close',
              'peripherals:Mock:UpdateDelayJitter',
              'peripherals:Beacon:Close',
              'peripherals:Beacon:UpdateDelayJitter'
            ]
          }
        ]
      }
    ]
  }
};
