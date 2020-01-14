<template>
  <div class="c3checkbox-wrapper">
    <div class="c3checkbox-row" v-on:click="clickOnLabel">
      {{ legend }} &nbsp;
      <span class="icon help" v-if="hasHelp">
        <div class="help-text">{{ help }}</div>
      </span>
    </div>
    <div class="c3toggle" :class="{ disabled: isDisabled }">
      <input
        v-bind="$attrs"
        class="c3toggle-input"
        ref="booleanCheckbox"
        type="checkbox"
        :id="inputUID"
        :name="inputUID"
        :checked="getIsChecked"
        @change="toogleToggle"
        :disabled="disabled"
      />
      <label class="c3toggle-label" @click="clickOnLabel"></label>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Mixins } from 'vue-property-decorator';

import C3FormElement from '@/components/form/C3FormElement';

import C3 from '@/c3';

@Component
export default class Toggle extends Mixins(C3, C3FormElement) {
  @Prop() public checked!: string;

  public isChecked: boolean = this.getIsChecked;

  get getIsChecked() {
    if (
      this.checked &&
      typeof this.checked === 'boolean' &&
      this.checked === true
    ) {
      return true;
    }
    return false;
  }

  public mounted(): void {
    (this.$refs
      .booleanCheckbox as HTMLInputElement).checked = this.getIsChecked;
  }

  // boolean true or false, nothing to validate here
  public toogleToggle(): void {
    this.isChecked = !this.isChecked;
    this.$emit('change', {
      value: this.isChecked === true ? true : false,
      valid: true
    });
  }

  public clickOnLabel(): void {
    this.toogleToggle();
    // (this.$refs.booleanCheckbox as HTMLInputElement).checked = this.isChecked;
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3checkbox
  &-row
    display: flex
    align-items: center
  &-wrapper
    display: flex
    position: relative
    height: 32px
    align-items: center
    width: 100%
    justify-content: space-between
    .icon.help
      position: relative
      .help-text
        display: none
      &:hover .help-text
        position: absolute
        right: 0
        top: 24px
        display: block
        position: absolute
        font-family: "Roboto"
        font-size: 12px
        color: $color-grey-400
        background-color: $color-grey-900
        border-radius: 2px
        width: max-content
        padding: 4px 8px
        max-width: 400px
        z-index: 13
.c3toggle
  display: inline-block
  position: relative
  margin: 0
  &-input
    width: 36px
    height: 20px
    opacity: 0
    z-index: 0
  // Unchecked
  &-label
    display: block
    padding: 0 0 0 44px
    cursor: pointer

    &:before
      content: ''
      position: absolute
      top: 5px
      left: 0
      width: 37px
      height: 14px
      background-color: $color-grey-400
      border: 1px solid $color-grey-500
      border-radius: 14px
      z-index: 1
      transition: background-color 0.28s cubic-bezier(.4, 0, .2, 1)

    &:after
      content: ''
      position: absolute
      top: 3px
      left: 0
      width: 20px
      height: 20px
      background-color: $color-grey-500
      border-radius: 14px
      box-shadow: 0 2px 2px 0 rgba(0, 0, 0, .14),0 3px 1px -2px rgba(0, 0, 0, .2), 0 1px 5px 0 rgba(0, 0, 0, .12)
      z-index: 2
      transition: all 0.28s cubic-bezier(.4, 0, .2, 1)
      transition-property: left, background-color
  // Checked
  &-input:checked + &-label
    &:before
      background-color: $color-blue-200
      border: 1px solid $color-blue-500
    &:after
      left: 20px
      background-color: $color-blue-c3
  &.disabled
    .c3toggle-label
      &:before
        background-color: $color-grey-700
        border: 1px solid $color-grey-500
      &:after
        background-color: $color-grey-500
    .c3toggle-input:checked + .c3toggle-label
      &:before
        background-color: #5B8E7C
        border: 1px solid #1B6C51
      &:after
        background-color: $color-labs-800
</style>
