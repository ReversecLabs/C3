<template>
  <transition-group name="slide" tag="ul" class="c3notify">
    <li
      v-for="notify in notifies"
      :key="notify.id"
      :class="'c3notify-'+notify.type"
      style="right: 0"
    >
      <h1 v-if="notify.title">{{ notify.title }}</h1>
      <p>{{ notify.message }}</p>
      <span class="c3notify-close icon close" v-on:click.self="deleteNotify(notify.id)"></span>
    </li>
  </transition-group>
</template>

<script lang="ts">
import Vue from 'vue';
import { namespace } from 'vuex-class';
import { Component, Mixins } from 'vue-property-decorator';

import { Notify, RemoveNotifyFn } from '@/store/NotifyModule';

const NotifyModule = namespace('notifyModule');

@Component
export default class Notification extends Vue {
  @NotifyModule.Getter public getNotifies!: Notify[];

  @NotifyModule.Mutation public removeNotify!: RemoveNotifyFn;

  get notifies() {
    return this.getNotifies;
  }

  public deleteNotify(id: string): void {
    this.removeNotify(id);
  }
}
</script>

<style lang="sass">
@import '~@/scss/colors.scss'
.c3notify
  display: block
  position: fixed
  background-color: transparent
  width: 450px
  max-height: 100vh
  height: auto
  margin: 3rem calc((100vw - 450px) / 2) 3rem auto
  padding: 0
  bottom: 0
  right: 0
  z-index: 17
  list-style: none
  li
    transition: all .25s cubic-bezier(0, -0.05, 0.33, 0.99)
  .slide-enter-active, .slide-leave-active
    transition: all .5s cubic-bezier(0, -0.05, 0.33, 0.99)
  .slide-enter
    transform: translateY(10vh) scale(0.9)
    opacity: 0
  .slide-leave-to
    transform: translateY(10vh) scale(0.9)
    opacity: 0
  &-info, &-error
    display: block
    background-color: $color-grey-700
    opacity: 1
    position: relative
    min-height: 40px
    margin: 1rem
    padding: 1rem
    box-shadow: 0px 4px 4px rgba(0, 0, 0, 0.25)
    border-radius: 2px
    right: calc(-50vw - 225px)
    h1
      margin: 0
      padding: 0
      font-family: "Roboto Mono"
      font-weight: 500
      font-size: 18px
      line-height: 25px
      letter-spacing: -0.05em
      color: $color-grey-400
    p
      margin: 0
      padding: 0 12px 0 0
      font-size: 12px
      line-height: 14px
      color: $color-grey-000
    h1+p
      margin-top: .5rem
  &-info
    border-left: 8px solid $color-blue-c3
  &-error
    border-left: 8px solid $color-red-500
  &-close
    position: absolute
    top: .5rem
    right: .5rem
    cursor: pointer
</style>
