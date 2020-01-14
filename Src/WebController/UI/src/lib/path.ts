import { namespace } from 'vuex-class';
import { Vue, Component } from 'vue-property-decorator';
import { NodeKlass, C3Node, C3Edge, nullNode } from '@/types/c3types';

const C3Module = namespace('c3Module');

/**
 * Path finding Class for Highlight the path on the graph from the selected node
 * to the gateway
 *
 * @export
 * @class Path
 * @extends {Vue}
 */
@Component
export default class FindThePathToGateway extends Vue {
  @C3Module.Getter public getNodes!: C3Node[];
  @C3Module.Getter public getEdges!: C3Edge[];

  private startNode: C3Node = nullNode;
  private paths: string[] = [];
  private nextNode!: C3Node;

  get targetNode() {
    return (
      this.getNodes.find(node => {
        return node.klass === NodeKlass.Gateway;
      }) || nullNode
    );
  }

  public findPath(nodeId: string) {
    this.setStartNode(nodeId);

    this.paths = [];

    this.paths.push(this.startNode!.uid);

    let iterations = 0;

    if (this.hasPathEndpoints()) {
      return [];
    }

    while (!!this.startNode && this.startNode.uid !== this.targetNode.uid) {
      // set the next node equal to the current node
      this.nextNode = this.startNode;

      // set the next node if the start node is channel
      this.handleNodeChannel();

      // set the next node if the start node is connector or pheripheral
      this.handleConnectorAndPeripheral();

      // set the next node if the start node is relay
      this.handleRelay();

      // set start node to the next node towards the gateway
      this.setStartNode(this.nextNode.uid);

      // If something goes wrong, don't let the browser to stuck in an infinite loop.
      iterations++;

      // check we found the gateway or accidentaly stuck inside an infinite loop.
      this.checkEndLoop(iterations);
    }

    return this.paths;
  }

  // find the start node by Id and set it to the startNode
  private setStartNode(nodeId: string): void {
    this.startNode =
      this.getNodes.find(node => {
        return node.uid === nodeId;
      }) || nullNode;
  }

  // check booth start end target node has a valid NodeKlass
  private hasPathEndpoints(): boolean {
    return (
      this.startNode.klass === NodeKlass.Undefined ||
      this.targetNode.klass === NodeKlass.Undefined
    );
  }

  private handleNodeChannel() {
    return this.isChannel(this.startNode) && this.setNextNodeForChannel();
  }

  private handleConnectorAndPeripheral() {
    return (
      this.isStartNodeConnectorOrPeripheral() && this.setNextAndParentNode()
    );
  }

  private handleRelay() {
    return this.isStartNodeRelay() && this.setNextNodeForRelay();
  }

  // don't let the loop run more than 100 times (possible infinite loop)
  private checkEndLoop(iterations: number) {
    if (iterations > 100) {
      this.paths = [];
      this.setStartNode(this.targetNode.uid);
    }
  }

  // get the parent node for the startNode
  private getParentNode(): C3Node {
    return (
      this.getNodes.find(node => {
        return node.uid === this.startNode!.parentId;
      }) || nullNode
    );
  }

  private isStartNodeConnectorOrPeripheral(): boolean {
    return (
      this.startNode.klass === NodeKlass.Peripheral ||
      this.startNode.klass === NodeKlass.Connector
    );
  }

  private isChannel(node: C3Node): boolean {
    return node.klass === NodeKlass.Channel;
  }

  private isStartNodeRelay(): boolean {
    return this.startNode.klass === NodeKlass.Relay;
  }

  private isReturnChannel(node: C3Node): boolean {
    return node.isReturnChannel === true;
  }

  // find all the neighbours for the channel by the edges
  private getChannelNeighbours(): C3Edge[] {
    return this.getEdges.filter(edge => {
      return (
        edge.to === this.startNode!.uid || edge.from === this.startNode!.uid
      );
    });
  }

  // find all the neighbours for the relay by the edges
  private getRelayNeighbours(): C3Edge[] {
    return this.getEdges.filter(edge => {
      return edge.from === this.startNode!.uid;
    });
  }

  // look for possible neighbour on the edges by the uid
  // target: Enum ['from', 'to']
  private getPossibeNext(neighbour: C3Edge, target: string): C3Node {
    return (
      this.getNodes.find(node => {
        return node.uid === neighbour[target];
      }) || nullNode
    );
  }

  private insertParentNodeToPaths() {
    return (
      this.getParentNode().klass !== NodeKlass.Undefined &&
      this.paths.push(this.nextNode!.uid)
    );
  }

  private setNextAndParentNode(): void {
    // The parent is the way to find the gateway
    this.nextNode = this.getParentNode();
    this.insertParentNodeToPaths();
  }

  private setAndInsertNextNode(node: C3Node): void {
    // We found the way to the gateway
    this.nextNode = node;
    this.paths.push(node.uid);
  }

  // for not return channel the parent is the next node is the next step towards the gateway
  private setNextNodeForChannel(): void {
    if (this.isReturnChannel(this.startNode)) {
      this.setNextNodeForReturnChannel();
    } else {
      this.setNextAndParentNode();
    }
  }

  private setNextNodeForReturnChannel(): void {
    // The parent is in the oposite direction as for the normal channel
    // and we using the edge to get the path
    this.getChannelNeighbours().forEach(neighbour => {
      const possibleNext = this.getPossibeNext(neighbour, 'from');
      if (this.isChannel(possibleNext)) {
        this.setAndInsertNextNode(possibleNext);
      }
    });
  }

  // for relay we use the edge to found the way to the gateway
  private setNextNodeForRelay(): void {
    this.getRelayNeighbours().forEach(neighbour => {
      const possibleNext = this.getPossibeNext(neighbour, 'to');
      if (this.isReturnChannel(possibleNext)) {
        this.setAndInsertNextNode(possibleNext);
      }
    });
  }
}
