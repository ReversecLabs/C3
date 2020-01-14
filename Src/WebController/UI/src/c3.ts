import { Vue, Component } from 'vue-property-decorator';
import { namespace } from 'vuex-class';

import { GetNodeKlassFn } from '@/store/C3Module';
import { Notify, InsertNotifyFn } from '@/store/NotifyModule';
import { NewModalFn, CloseModalFn } from '@/store/ModalModule';
import { GetTypeNameForInterfaceFn } from '@/store/C3Capability';
import { C3Node, C3Command, NodeKlass, nullNode } from '@/types/c3types';

const C3Module = namespace('c3Module');
const NotifyModule = namespace('notifyModule');
const ModalModule = namespace('modalModule');
const C3Capability = namespace('c3Capability');
const PaginateModule = namespace('paginateModule');

@Component
export default class C3 extends Vue {
  @ModalModule.Mutation public newModal!: NewModalFn;
  @ModalModule.Mutation public closeModal!: CloseModalFn;
  @ModalModule.Mutation public closeModalAll!: CloseModalFn;

  @NotifyModule.Action public insertNotify!: InsertNotifyFn;

  @C3Capability.Getter
  public getTypeNameForInterface!: GetTypeNameForInterfaceFn;

  @PaginateModule.Getter public getItemPerPage!: number;
  @PaginateModule.Getter public getActualPage!: number;

  @C3Module.Getter public getNodeKlass!: GetNodeKlassFn;
  @C3Module.Getter public getGateway!: C3Node;

  get itemPerPage() {
    return this.getItemPerPage;
  }

  get actualPage() {
    return this.getActualPage;
  }

  get maxIndex() {
    return this.itemPerPage * this.actualPage;
  }

  get minIndex() {
    return this.maxIndex - this.itemPerPage;
  }

  public openModal(id: string, modal: string, options: any = {}) {
    this.newModal({
      modalTarget: modal,
      modalTargetId: id,
      modalOptions: options
    });
  }

  public closeThisModal(): void {
    this.closeModal();
  }

  public closeAllModal(): void {
    this.closeModalAll();
  }

  public addNotify(notify: Notify): void {
    this.insertNotify(notify);
  }

  public interfaceTypeName(c3Interface: C3Node): string {
    if (c3Interface && c3Interface.type !== null) {
      if (c3Interface.klass) {
        return this.getTypeNameForInterface(
          c3Interface.type,
          c3Interface.klass
        );
      }
      this.addNotify({
        type: 'error',
        message:
          'Interface Type cannot be determined. Must be a channel, connector or peripheral.'
      });
    }
    return '';
  }

  public interfaceType(c3Channel: C3Node): string {
    if (!!c3Channel.isReturnChannel) {
      return 'Return Channel';
    }
    if (!!c3Channel.isNegotiationChannel) {
      return 'Negotiation Channel';
    }

    return '';
  }

  get gateway() {
    if (this.getGateway === undefined) {
      return nullNode;
    }
    return this.getGateway;
  }

  public commandType(c3Command: C3Command): string {
    if (c3Command.interfaceId && c3Command.interfaceId !== undefined) {
      if (c3Command.relayAgentId && c3Command.relayAgentId !== undefined) {
        return this.getNodeKlass(
          c3Command.interfaceId + '-' + c3Command.relayAgentId
        );
      }
      return this.getNodeKlass(c3Command.interfaceId + '-' + this.gateway.id);
    }
    if (c3Command.relayAgentId && c3Command.relayAgentId !== undefined) {
      return NodeKlass.Relay;
    }
    return NodeKlass.Gateway;
  }

  public commandTypeId(c3Command: C3Command): string {
    if (c3Command.relayAgentId && c3Command.relayAgentId !== undefined) {
      return '' + c3Command.relayAgentId;
    }
    if (c3Command.interfaceId && c3Command.interfaceId !== undefined) {
      return '' + c3Command.interfaceId;
    }
    if (this.gateway) {
      return '' + this.gateway.id;
    }
    return 'error';
  }

  public isCommandPending(
    c3Command: C3Command,
    returnClass: boolean = false
  ): string {
    if (returnClass) {
      if (c3Command.isPending === true) {
        return 'Pending';
      }
      return 'Complete';
    }
    if (c3Command.isPending === true) {
      return 'is-complete';
    }
    return 'not-complete';
  }

  public handleGlobalKeyDown(e: any): void {
    if (e.keyCode === 27) {
      this.closeAllModal();
    }
  }

  public unixTimeToString(unixTimestamp: number) {
    const time = new Date(unixTimestamp * 1000);
    let timeStr = time.toISOString();
    timeStr = timeStr.replace(/-/g, '/');
    timeStr = timeStr.replace('T', ' ');
    timeStr = timeStr.replace('.000Z', '');
    return timeStr;
  }
}
