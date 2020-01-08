<template>
  <div class="c3select" :class="{ disabled: isDisabled }">
    <div
      class="c3select-close"
      v-on:click.self="toggleSelect()"
      v-show="isOpen"
    ></div>
    <div class="c3select-select">
      <span
        class="c3select-selected"
        :class="{ 'c3select-border': hasBorder }"
        v-on:click.self="toggleSelect()"
      >
        {{ selectedValue }}
      </span>
      <span class="c3select-legend" v-if="legend">
        {{ legend }}
      </span>
      <span
        class="c3select-icon icon"
        :class="dropDownIcon"
        v-on:click.self="toggleSelect()"
      ></span>
    </div>
    <ul
      class="c3select-options"
      v-show="isOpen"
      :class="{ 'c3select-direction-up': directionReverse }"
      :style="selectUlStyle"
    >
      <li
        v-for="(value, id) in options"
        class="c3select-option"
        :class="{ selected: isSelected(id) }"
        :key="id"
        v-on:click.self="selectAndClose(id)"
      >
        {{ value }}
      </li>
    </ul>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Mixins } from 'vue-property-decorator';

import C3 from '@/c3';
import C3FormElement from './C3FormElement';

@Component
export default class Select extends Mixins(C3, C3FormElement) {
  @Prop() public up!: boolean;
  @Prop() public legend!: string;
  @Prop() public border!: boolean;
  @Prop() public selected!: string;
  @Prop() public options!: { [key: string]: string };
  @Prop() public feedback!: string;

  public isOpen: boolean = false;
  public hasBorder: boolean = this.border || false;
  public directionReverse: boolean = this.up || false;
  public selectRef: string = Math.random()
    .toString(36)
    .substring(2);
  public selectUlStyle: string = '';

  get dropDownIcon() {
    return this.isOpen ? 'carrotup' : 'carrotdown';
  }

  get selectedValue(): string {
    let value: string = '';
    Object.keys(this.options).forEach(e => {
      if (this.selected === e) {
        value = this.options[e];
      }
    });
    return value;
  }

  public mounted(): void {
    if (!this.up) {
      this.calculateSelectUlOffset();
    }
  }

  public isSelected(selectedId: string) {
    return this.selected === selectedId ? 'selected' : '';
  }

  public toggleSelect(): void {
    this.calculateSelectUlOffset();
    if (!this.isDisabled) {
      this.isOpen = !this.isOpen;
    }
  }

  public selectAndClose(value: string): void {
    if (this.feedback === 'validated') {
      this.$emit('change', { value, valid: true });
    } else {
      this.$emit('change', value);
    }
    this.toggleSelect();
  }

  public calculateSelectUlOffset(): void {
    const rect = this.$el.getBoundingClientRect();
    const scrollLeft =
      window.pageXOffset || document.documentElement.scrollLeft;
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    if (this.directionReverse) {
      this.selectUlStyle =
        `position: fixed; margin-bottom: -31px; bottom: calc(100vh - ${rect.top +
          scrollTop}px);` +
        ` left: ${rect.left + scrollLeft}px; width: ${rect.width}px;`;
    } else {
      this.selectUlStyle =
        `position: fixed; margin-top: 31px; top: ${rect.top + scrollTop}px;` +
        ` left: ${rect.left + scrollLeft}px; width: ${rect.width}px;`;
    }
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3select
  position: relative
  display: flex
  flex-grow: 1
  max-height: 32px
  background-color: inherit
  margin-bottom: 16px
  &.disabled
    color: $color-grey-500
    .c3select-border
      border: 1px solid $color-grey-500
    .c3select-legend
      color: $color-grey-500
  &-close
    display: block
    position: fixed
    background-color: transparent
    width: 100vw
    height: 100vh
    margin: 0
    padding: 0
    top: 0
    left: 0
    z-index: 12
  &-select
    position: relative
    display: flex
    flex-grow: 1
    max-height: 32px
    background-color: inherit
    align-items: center
  &-selected
    font-family: Roboto
    font-style: normal
    font-weight: normal
    font-size: inherit
    line-height: 16px
    display: flex
    align-items: center
    height: 32px
    width: 100%
    padding-left: .5rem
    padding-right: 1rem
    position: relative
    outline: none
  &-border
    border: 1px solid $color-grey-000
    border-radius: 2px
    padding-left: 1rem
  &-legend
    position: absolute
    font-size: 10px
    line-height: 12px
    color: $color-grey-000
    background-color: inherit
    left: .5rem
    top: -.4rem
    padding-left: .5rem
    padding-right: .5rem
  .icon
    position: absolute
    right: 4px
    top: 4px
    cursor: pointer
  &-options
    position: absolute
    left: 0
    margin: 0
    padding: 0
    list-style: none
    z-index: 15
    border: 1px solid $color-grey-500
    border-radius: 0 0 2px 2px
    width: 100%
    top: 31px
    max-height: 250px
    overflow-y: auto
    .selected
      color: $color-grey-000
      font-weight: 700
    &.c3select-direction-up
      top: unset
      bottom: 0
    .c3select-option
      height: 32px
      display: flex
      align-items: center
      padding-left: .5rem
      padding-right: .5rem
      cursor: pointer
      &:hover
        background-color: $color-grey-800
</style>
