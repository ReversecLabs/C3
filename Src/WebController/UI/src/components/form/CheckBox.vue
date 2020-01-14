<template>
  <div class="c3checkbox-wrapper">
    <span class="icon help" v-if="hasHelp">
      <div class="help-text">
        {{ help }}
      </div>
    </span>
    <label class="icon checkbox" :class="getIconKlass" :for="inputUID">
      {{ legend }}
      <input
        ref="booleanCheckbox"
        type="checkbox"
        value="None"
        :id="inputUID"
        :name="inputUID"
        v-model="isChecked"
        true-value="true"
        false-value="false"
        @change="toogleCheckBox"
        :disabled="disabled"
        :autocomplete="autocomplete"
      />
    </label>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Mixins } from 'vue-property-decorator';

import C3FormElement from '@/components/form/C3FormElement';

import C3 from '@/c3';

@Component
export default class CheckBox extends Mixins(C3, C3FormElement) {
  @Prop() public value!: string;

  public isChecked: string = this.getIsChecked;

  get getIconKlass() {
    const checked: string = this.isChecked === 'true' ? '-on' : '-off';
    const disabled: string = this.isDisabled ? '--disabled' : '';
    return `checkbox${checked}${disabled}`;
  }

  get getIsChecked() {
    if (this.value && typeof this.value === 'boolean' && this.value === true) {
      return 'true';
    }
    return 'false';
  }

  public mounted(): void {
    this.toogleCheckBox();
  }

  // boolean true or false, nothing to validate here
  public toogleCheckBox(): void {
    const isCheckedValue = this.isChecked === 'true' ? true : false;
    this.$emit('change', {
      value: isCheckedValue,
      valid: true
    });
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3checkbox
  &-wrapper
    display: flex
    position: relative
    .icon.help
      position: absolute
      z-index: 12
      right: 3px
      top: -5px
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
    .icon.checkbox
      display: flex
      align-items: center
      padding-left: 32px
      position: relative
      left: 0
      width: auto
      background-position-x: left
      &:hover
        background-position-x: left
    input[type=checkbox]
      visibility: hidden
</style>
