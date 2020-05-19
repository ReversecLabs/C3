<template>
  <div class="c3canvas" :class="{ 'c3canvas-fs': isFullscreen }">
    <div ref="c3canvas" id="c3canvas"></div>
    <span
      class="c3canvas-fs-btn icon"
      :class="fullscreenIcon"
      @click="isFullscreen = !isFullscreen"
    ></span>
    <span class="c3canvas-more-btn icon more"></span>
    <ul class="c3canvas-menu">
      <li class="c3canvas-menu-item">
        <Toggle
          key="toggle-tree-view-button"
          legend="Tree View"
          @change="toggleTreeView"
          :checked="getTreeView"
          :disabled="false"
        />
      </li>
      <li class="c3canvas-menu-item">
        <Toggle
          key="toggle-interfaces-button"
          legend="Interfaces"
          @change="toggleInterfaces($event)"
          :checked="getInterfaces"
          :disabled="false"
        />
      </li>
      <li class="c3canvas-menu-item">
        <Toggle
          key="toggle-labels-button"
          legend="Labels"
          @change="toggleLabels($event)"
          :checked="getShowLabels"
          :disabled="false"
        />
      </li>
      <li class="c3canvas-menu-item">
        <Toggle
          key="toggle-physics-button"
          legend="Physics"
          @change="togglePhysics($event)"
          :checked="getPhysics"
          :disabled="false"
        />
      </li>
      <li class="c3canvas-menu-item">
        <Toggle
          key="toggle-smooth-edges"
          legend="Smooth Edges"
          @change="toggleSmoothEdges($event)"
          :checked="getSmoothEdges"
          :disabled="false"
        />
      </li>
      <li class="c3canvas-menu-item" @click="reloadGraph">Reload Graph</li>
      <li class="c3canvas-menu-divider"></li>
      <li class="c3canvas-menu-item" @click="openModal('', 'CREATE_GATEWAY')">
        New Gateway
      </li>
      <li class="c3canvas-menu-item" @click="openModal('', 'CREATE_RELAY')">
        New Relay
      </li>
    </ul>
    <div class="progress-bar">
      <div class="progress-bar-status" id="progress-bar-status"></div>
    </div>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { VisOptions } from '@/options';
import { Component, Watch, Mixins } from 'vue-property-decorator';
import { DataView, Options } from 'vis-network';
import { DataSet } from 'vis-data/peer/esm/vis-data';
import { Network } from 'vis-network/peer/esm/vis-network';

import { NodeKlass, C3Node, C3Edge, nullNode } from '@/types/c3types';
import { GetNodeKlassFn, FetchC3DataFn } from '@/store/C3Module';
import {
  SetOptionslFn,
  SetGraphDataFn,
  GenerateNodesFn,
  GenerateEdgesFn,
  SetOptionFn
} from '@/store/VisModule';

import C3 from '@/c3';
import Toggle from '@/components/form/Toggle.vue';
import FindThePathToGateway from '@/lib/path';

const C3Module = namespace('c3Module');
const VisModule = namespace('visModule');

@Component({
  components: {
    Toggle
  }
})
export default class Canvas extends Mixins(C3, FindThePathToGateway) {
  get fullscreenIcon() {
    return this.isFullscreen ? 'zoomin' : 'fullscreen';
  }

  get graphOtions() {
    return this.getOptions;
  }

  get graphData() {
    return this.getGrapData;
  }

  get getTreeView() {
    return this.graphOtions.layout.hierarchical.enabled;
  }

  get getPhysics() {
    return this.graphOtions.physics.enabled;
  }

  get getInterfaces() {
    return this.getShowInterfaces;
  }

  get getSmoothEdges() {
    return this.isSmooth;
  }

  @VisModule.Action public generateNodes!: GenerateNodesFn;
  @VisModule.Action public generateEdges!: GenerateEdgesFn;

  @VisModule.Getter public getVisNodes!: any;
  @VisModule.Getter public getVisEdges!: any;
  @VisModule.Getter public getGrapData!: object;
  @VisModule.Getter public getOptions!: Options;
  @VisModule.Getter public getShowInterfaces!: boolean;
  @VisModule.Getter public getShowLabels!: boolean;

  @VisModule.Mutation public setPhysics!: SetOptionFn;
  @VisModule.Mutation public setTreeView!: SetOptionFn;
  @VisModule.Mutation public setOptions!: SetOptionslFn;
  @VisModule.Mutation public setSmoothEdge!: SetOptionFn;
  @VisModule.Mutation public setGraphData!: SetGraphDataFn;
  @VisModule.Mutation public setShowInterfaces!: SetOptionFn;
  @VisModule.Mutation public setShowLabels!: SetOptionFn;

  @C3Module.Action public fetchGateway!: FetchC3DataFn;

  @C3Module.Getter public getNodeKlass!: GetNodeKlassFn;

  public container: any = null;
  public isSmooth: boolean = false;
  public isFullscreen: boolean = false;
  public lastClickNodeId: string = '';

  public mounted(): void {
    this.createVisCanvas();
  }

  public createVisCanvas(): void {
    this.container = this.$refs.c3canvas;
    (window as any).networkc3 = new Network(
      this.container,
      this.getGrapData,
      this.graphOtions
    );

    (window as any).networkc3.on('click', (params: any) => {
      const nodeid = (window as any).networkc3.getNodeAt(params.pointer.DOM);
      if (this.lastClickNodeId === nodeid) {
        if (!!nodeid) {
          this.openModal(nodeid, this.nodeKlass(nodeid));
        }
      } else {
        this.lastClickNodeId = nodeid;
      }
      this.deselectNodes();
      this.clearPath();
      if (!!nodeid) {
        this.selectNode(nodeid);
      }
    });

    (window as any).networkc3.on('startStabilizing', (params: any) => {
      const progressBarStatus = document.getElementById('progress-bar-status');
      if (progressBarStatus !== null) {
        progressBarStatus.style.width = '1px';
      }
    });

    (window as any).networkc3.on('stabilizationProgress', (params: any) => {
      const status = Math.floor(
        params.iterations / this.getOptions.physics.stabilization.updateInterval
      );
      const progressBarStatus = document.getElementById('progress-bar-status');
      if (progressBarStatus !== null) {
        progressBarStatus.style.width = status + '%';
      }
    });

    (window as any).networkc3.on('stabilized', (params: any) => {
      const progressBar = document.getElementById('progress-bar-status');
      if (progressBar !== null) {
        progressBar.style.width = '1px';
      }
    });
  }

  public nodeKlass(nodeid: string): NodeKlass {
    return this.getNodeKlass(nodeid);
  }

  public toggleTreeView(b: any): void {
    this.setTreeView(b.value);
    (window as any).networkc3.setOptions(this.graphOtions);
    this.setGraphData();
  }

  public togglePhysics(b: any): void {
    this.setPhysics(b.value);
    (window as any).networkc3.setOptions(this.graphOtions);
    this.setGraphData();
  }

  public toggleInterfaces(b: any): void {
    this.setShowInterfaces(b.value);
    this.generateNodes();
    this.generateEdges();
    this.setGraphData();
  }

  public toggleLabels(b: any): void {
    this.setShowLabels(b.value);
    this.generateNodes();
    this.generateEdges();
    this.setGraphData();
  }

  public toggleSmoothEdges(b: any): void {
    this.isSmooth = b.value;
    this.setSmoothEdge(b.value);
    (window as any).networkc3.setOptions(this.graphOtions);
    this.setGraphData();
  }

  public reloadGraph(): void {
    const o = this.graphOtions;
    o.layout.randomSeed = Math.floor(Math.random() * 785496) + 1;
    (window as any).networkc3.setOptions(o);
    this.setGraphData();
  }

  public deselectNodes(): void {
    this.getVisNodes.forEach((nodeId: any) => {
      (window as any).networkc3.body.data.nodes.update([
        {
          id: nodeId.id,
          shadow: {
            enabled: false
          }
        }
      ]);
    });
  }

  public clearPath(): void {
    this.getVisEdges.forEach((edge: any) => {
      const tmpEdge = (window as any).networkc3.body.data.edges.get(edge.id);
      if (
        (!!tmpEdge.color && Object.keys(tmpEdge.color).length !== 0) ||
        (!!tmpEdge.width && tmpEdge.width !== 1)
      ) {
        (window as any).networkc3.body.data.edges.update([
          {
            id: edge.id,
            color: {},
            width: 1
          }
        ]);
      }
    });
  }

  public selectNode(nodeId: string): void {
    (window as any).networkc3.body.data.nodes.update([
      {
        id: nodeId,
        shadow: {
          enabled: true
        }
      }
    ]);

    const paths = this.getPathsFromGateway(nodeId);
    this.getVisEdges.forEach((edge: any) => {
      if (!!paths && paths.includes(edge.from) && paths.includes(edge.to)) {
        (window as any).networkc3.body.data.edges.update([
          {
            id: edge.id,
            color: {
              color: '#AB61F6'
            },
            width: 4
          }
        ]);
      }
    });
  }

  public getPathsFromGateway(nodeId: string) {
    return this.findPath(nodeId);
  }
}
</script>

<style lang="sass">
@import '~@/scss/colors.scss'
.c3canvas
  position: relative
  display: flex
  flex-direction: column
  flex-shrink: 1
  margin: 0 auto 0 auto
  padding: 0
  border: 0.75px solid $color-blue-c3
  box-sizing: border-box
  box-shadow: 0px 1px 2px rgba(0, 0, 0, 0.5)
  border-radius: 2px
  width: 100%
  max-width: 1200px
  height: 600px
  background-color: $color-grey-bg
  .progress-bar
    position: absolute
    display: flex
    left: 0
    bottom: 0
    width: 100%
    height: 10px
    background: transparent
    .progress-bar-status
      position: relative
      background-color: $color-blue-c3
      width: 0%
      height: 100%
  &-toggle-layout.c3canvas-toggle-layout, &-toggle-interfaces.c3canvas-toggle-interfaces
    position: relative
    cursor: pointer
  &-toggle-layout.c3canvas-toggle-layout
    margin-bottom: .5rem
  &-toggle-interfaces.c3canvas-toggle-interfaces
    margin-top: .5rem
  &-fs-btn
    position: absolute
    cursor: pointer
    right: 50px
    top: 23px
  &-more-btn
    position: absolute
    cursor: pointer
    right: 21px
    top: 23px
  &-menu
    display: none
    flex-direction: column
    position: absolute
    right: 21px
    top: 33px
    flex-direction: column
    padding: 0
    background: $color-grey-c3
    box-shadow: 0px 12px 24px rgba(0, 0, 0, 0.15)
    border-radius: 2px
    list-style: none
    min-width: 180px
    &-item
      display: flex
      align-items: center
      font-size: 14px
      line-height: 16px
      color: $color-grey-000
      height: 32px
      padding: 0 8px
      &:hover
        background-color: $color-grey-900
        cursor: pointer
    &-divider
      height: 0
      width: 100
      border-bottom: 1px solid $color-grey-800
    &:hover
      display: flex
  &-more-btn:hover + .c3canvas-menu
    display: flex
  #c3canvas
    width: inherit
    height: inherit
    padding: 2px
    background-color: transparent
    div.vis-network div.vis-navigation div.vis-button:hover
      box-shadow: none
    div.vis-network div.vis-navigation div.vis-button:active
      box-shadow: none
.c3canvas-fs
  position: fixed
  top: 16px
  left: 16px
  max-width: 100vw
  width: calc(100vw - 32px)
  height: calc(100vh - 32px)
  border: 0.75px solid $color-blue-c3
  z-index: 9
  .c3canvas-fs-btn
    z-index: 10
  .c3canvas-menu-btn
    z-index: 10

/* Begin: VIS CSS Overwrite*/
#c3canvas
  div.vis-network
    border: none
    outline: none
  div.vis-network div.vis-navigation div.vis-button
    width: 34px
    height: 34px
    -moz-border-radius: 17px
    border-radius: 17px
    position: absolute
    display: inline-block
    background-position: 2px 2px
    background-repeat: no-repeat
    cursor: pointer
    -webkit-touch-callout: none
    -webkit-user-select: none
    -khtml-user-select: none
    -moz-user-select: none
    -ms-user-select: none
    user-select: none
  div.vis-network div.vis-navigation div.vis-button:hover
    box-shadow: none
  div.vis-network div.vis-navigation div.vis-button:active
    box-shadow: none
  div.vis-network div.vis-navigation div.vis-button.vis-up
    background-image: url("data:image/svg+xml,%0A%3Csvg width='24' height='24' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath fill-rule='evenodd' clip-rule='evenodd' d='M12 8L6 14L7.4 15.4L12 10.8L16.6 15.4L18 14L12 8Z' fill='white'/%3E%3C/svg%3E%0A")
    top: 19px
    left: 70px
  div.vis-network div.vis-navigation div.vis-button.vis-down
    background-image: url("data:image/svg+xml,%0A%3Csvg width='24' height='24' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath fill-rule='evenodd' clip-rule='evenodd' d='M12 16L18 10L16.6 8.6L12 13.2L7.4 8.6L6 10L12 16Z' fill='white'/%3E%3C/svg%3E%0A")
    top: 70px
    left: 70px
  div.vis-network div.vis-navigation div.vis-button.vis-left
    background-image: url("data:image/svg+xml,%0A%3Csvg width='24' height='24' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath fill-rule='evenodd' clip-rule='evenodd' d='M15.4 7.4L14 6L8 12L14 18L15.4 16.6L10.8 12L15.4 7.4Z' fill='white'/%3E%3C/svg%3E%0A")
    top: 70px
    left: 19px
  div.vis-network div.vis-navigation div.vis-button.vis-right
    background-image: url("data:image/svg+xml,%0A%3Csvg width='24' height='24' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath fill-rule='evenodd' clip-rule='evenodd' d='M8.59998 7.4L9.99998 6L16 12L9.99998 18L8.59998 16.6L13.2 12L8.59998 7.4Z' fill='white'/%3E%3C/svg%3E%0A")
    top: 70px
    left: 115px
  div.vis-network div.vis-navigation div.vis-button.vis-zoomIn
    background-image: url("data:image/svg+xml,%0A%3Csvg width='24' height='24' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath fill-rule='evenodd' clip-rule='evenodd' d='M12 19C15.866 19 19 15.866 19 12C19 8.13401 15.866 5 12 5C8.13401 5 5 8.13401 5 12C5 15.866 8.13401 19 12 19ZM12 21C16.9706 21 21 16.9706 21 12C21 7.02944 16.9706 3 12 3C7.02944 3 3 7.02944 3 12C3 16.9706 7.02944 21 12 21Z' fill='white'/%3E%3Cpath fill-rule='evenodd' clip-rule='evenodd' d='M17.4002 12.6001L17.4002 11.4001L12.6001 11.4001L12.6001 6.60001H11.4001L11.4001 11.4001L6.60002 11.4001L6.60002 12.6001L11.4001 12.6001V17.4002H12.6001V12.6001L17.4002 12.6001Z' fill='white'/%3E%3C/svg%3E")
    top: 19px
    left: 19px
  div.vis-network div.vis-navigation div.vis-button.vis-zoomOut
    background-image: url("data:image/svg+xml,%0A%3Csvg width='24' height='24' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath fill-rule='evenodd' clip-rule='evenodd' d='M12 19C15.866 19 19 15.866 19 12C19 8.13401 15.866 5 12 5C8.13401 5 5 8.13401 5 12C5 15.866 8.13401 19 12 19ZM12 21C16.9706 21 21 16.9706 21 12C21 7.02944 16.9706 3 12 3C7.02944 3 3 7.02944 3 12C3 16.9706 7.02944 21 12 21Z' fill='white'/%3E%3Cpath fill-rule='evenodd' clip-rule='evenodd' d='M17.4002 12.6001L17.4002 11.4001L12.6001 11.4001L12.1471 11.4001H11.7497L11.4001 11.4001L6.60002 11.4001L6.60002 12.6001L11.4001 12.6001H11.7497L12.1471 12.6001L12.6001 12.6001L17.4002 12.6001Z' fill='white'/%3E%3C/svg%3E%0A")
    top: 19px
    left: 115px
  div.vis-network div.vis-navigation div.vis-button.vis-zoomExtends
    background-image: url("data:image/svg+xml,%0A%3Csvg width='24' height='24' viewBox='0 0 24 24' fill='none' xmlns='http://www.w3.org/2000/svg'%3E%3Cpath d='M17 16L13 12V8.82C14.16 8.4 15 7.3 15 6C15 4.34 13.66 3 12 3C10.34 3 9 4.34 9 6C9 7.3 9.84 8.4 11 8.82V12L7 16H3V21H8V17.95L12 13.75L16 17.95V21H21V16H17Z' fill='white'/%3E%3C/svg%3E%0A")
    top: 19px
    right: 70px
/* End: VIS CSS Overwrite*/
</style>
