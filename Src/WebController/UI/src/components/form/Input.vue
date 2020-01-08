<template>
  <div class="c3input-wrapper">
    <span class="icon help" v-if="hasHelp">
      <div class="help-text">
        {{ help }}
      </div>
    </span>
    <span class="icon random" v-if="random" @click.self="onClickRandom"></span>
    <input
      v-bind="$attrs"
      ref="textinput"
      class="c3input-input"
      :class="{ dirty: isDirty }"
      type="text"
      v-model="inputText"
      @change="changeInputText"
      @focus="gainFocus()"
      @blur="lostFocus()"
      :disabled="isDisabled"
      v-validate="validate"
      :name="inputUID"
      :autocomplete="autocomplete"
    />
    <label
      class="c3input-label"
      :class="{ dirty: isDirty }"
      @click.self="clickOnLabel()"
    >
      {{ legend }}
    </label>
    <span class="error-message">{{ errors.first(inputUID) }}</span>
  </div>
</template>

<script lang="ts">
import { Component, Prop, Mixins } from 'vue-property-decorator';

import C3FormElement from '@/components/form/C3FormElement';

import C3 from '@/c3';

@Component({
  $_veeValidate: {
    validator: 'new'
  }
})
export default class Input extends Mixins(C3, C3FormElement) {
  @Prop() public value!: string;
  @Prop() public random!: string;
  @Prop() public validate!: string;

  public focused: boolean = false;
  public inputText: string = this.getValue;
  public intervalTimer: any = null;

  get getValue() {
    if ((this.value === '' || this.value === undefined) && this.random) {
      return this.rand(parseInt(this.random, 10));
    }
    return this.value || '';
  }

  get isDirty() {
    return !!this.value || !!this.inputText;
  }

  public mounted(): void {
    this.changeInputText();
    (window as any).addEventListener(
      'inputkeypress',
      this.handleEnterAndTabKeyDown,
      true
    );
  }

  public beforeDestroy(): void {
    (window as any).removeEventListener(
      'inputkeypress',
      this.handleEnterAndTabKeyDown,
      true
    );
  }

  public gainFocus(): void {
    this.focused = true;
    this.intervalTimer = setInterval(this.changeInputText, 500);
  }

  public lostFocus(): void {
    this.focused = false;
    clearInterval(this.intervalTimer);
    this.changeInputText();
  }

  public clickOnLabel(): void {
    (this.$refs.textinput as HTMLInputElement).focus();
  }

  public changeInputText() {
    this.$validator
      .verify((this.$refs.textinput as HTMLInputElement).value, this.validate)
      .then(valid => {
        const isValid = valid.valid;
        this.$emit('change', {
          value: this.inputText,
          valid: isValid
        });
      });
  }

  public handleEnterAndTabKeyDown(e: any): void {
    if (e.keyCode === 13 || e.keyCode === 9) {
      this.changeInputText();
    }
  }

  public rand(n: number) {
    if (n < 1) {
      n = 1;
    }
    if (n > 10) {
      n = 10;
    }
    return Math.random()
      .toString(36)
      .substring(2)
      .substr(0, n);
  }

  public onClickRandom() {
    this.inputText = this.rand(parseInt(this.random, 10));
    // We need to run the validation manualy because the value changed programaticaly
    // and not by user interaction.
    this.$validator.validate().then(valid => {
      this.changeInputText();
    });
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3input
  &-wrapper
    position: relative
    display: flex
    flex-grow: 1
    max-height: 32px
    background-color: inherit
    margin-bottom: 16px
    .icon.random
      position: absolute
      z-index: 12
      right: 27px
      top: 3px
    .icon.help
      position: absolute
      z-index: 12
      right: 3px
      top: 3px
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
    span.error-message
      color: $color-red-c3
      font-size: 12px
      line-height: 12px
      position: absolute
      right: 0rem
      bottom: -13px
  &-label
    font-size: 14px
    color: $color-grey-400
    background-color: inherit
    left: .5rem
    top: .6rem
    position: absolute
    padding-left: .5rem
    padding-right: .5rem
    transition-property: font-size, top, color
    transition-duration: .25s
    transition-delay: 0s
    &.dirty
      color: $color-grey-200
      font-size: 10px
      left: .5rem
      top: -.4rem
    &[disabled]
      color: $color-grey-500
  &-input
    background-color: inherit
    color: $color-grey-000
    font-family: "Roboto"
    font-size: 14px
    line-height: 16px
    display: block
    border: 1px solid $color-grey-400
    border-radius: 2px
    height: 32px
    width: 100%
    padding-left: 1rem
    padding-right: 1rem
    position: relativesdf
    outline: none
    &.dirty
      border: 1px solid $color-grey-000
      color: $color-grey-200
    &[aria-invalid="true"]
      border-color: $color-red-c3
      color: $color-red-c3
      & + label
        color: $color-red-c3
    &:active:not([disabled]), &:focus:not([disabled])
      border-color: $color-blue-500
      &:invalid
        border-color: $color-red-c3
        & + label
          color: $color-red-c3
      & + label
        color: $color-blue-500
      & + label
        font-size: 10px
        left: .5rem
        top: -.4rem
    &[disabled]
      border-color: $color-grey-500
      color: $color-grey-500
      & + label
        color: $color-grey-500
    &:invalid
      border-color: $color-red-c3
</style>
