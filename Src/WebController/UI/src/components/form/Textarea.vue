<template>
  <div class="c3textarea">
    <span class="icon help" v-if="hasHelp">
      <div class="help-text">
        {{ help }}
      </div>
    </span>
    <div class="textarea" :class="{ focus: focused }">
      <textarea
        class="c3textarea-input"
        :class="{ focus: focused }"
        rows="5"
        cols="33"
        ref="textareainput"
        type="checkbox"
        :id="inputUID"
        :name="inputUID"
        v-model="dataText"
        @input="updateTextarea"
        @focus="focused = true"
        @blur="lostFocus()"
        :disabled="disabled"
        :autocomplete="autocomplete"
      >
      </textarea>

      <label
        class="c3textarea-label"
        :class="{ dirty: isDirty, focus: focused }"
        @click.self="clickOnLabel()"
      >
        {{ legend }}
      </label>
      <label class="c3textarea-upload-button" for="payload-file">
        <span class="icon upload">
          <div class="help-text">
            Select file to upload...
          </div>
        </span>
      </label>
    </div>
    <input
      id="payload-file"
      type="file"
      style="visibility:hidden;"
      ref="fileinput"
      @change="updateTextfield"
    />
  </div>
</template>

<script lang="ts">
import { Component, Prop, Mixins } from 'vue-property-decorator';

import C3FormElement from '@/components/form/C3FormElement';

import C3 from '@/c3';

@Component
export default class Textarea extends Mixins(C3, C3FormElement) {
  @Prop() public value!: string;

  public dataText: string = '';
  public focused: boolean = false;

  get isDirty() {
    return !!this.value || !!this.dataText;
  }

  public mounted(): void {
    this.updateTextarea();
  }

  public lostFocus(): void {
    this.focused = false;
    this.updateTextarea();
  }

  // can be anything so nothing to validate here
  public updateTextarea(): void {
    this.$emit('change', {
      value: this.dataText,
      valid: true
    });
  }

  public clickOnLabel(): void {
    (this.$refs.textareainput as HTMLInputElement).focus();
  }

  public updateTextfield(): void {
    const reader = new FileReader();
    const file: any = this.$refs.fileinput as HTMLInputElement;
    let base64: string;

    reader.readAsDataURL(file.files[0]);

    reader.onload = () => {
      base64 = reader.result as string;
      if (!base64) {
        base64 = (base64 as string).replace(/^data:(.*;base64,)?/, '');
      }
      this.dataText = base64;
      this.updateTextarea();
      // If manualy delete the content and select the same file, we need to populate the data again.
      // To do this we need to reset the input field. If we don't do that selecting the same file
      // is not trigger the change event.
      try {
        (this.$refs.fileinput as HTMLInputElement).value = '';
        if ((this.$refs.fileinput as HTMLInputElement).value) {
          (this.$refs.fileinput as HTMLInputElement).type = 'text';
          (this.$refs.fileinput as HTMLInputElement).type = 'file';
        }
      } catch (e) {
        // tslint:disable-next-line:no-console
        console.error('Error during input element reset.');
      }
    };
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3textarea
  max-width: 868px
  padding: 0
  margin: 0
  position: relative
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
  &-upload-button
    position: absolute
    z-index: 12
    right: 30px
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
  .textarea
    width: 100%
    height: 100%
    margin: 0
    padding: 8px
    color: $color-grey-000
    background-color: $color-grey-900
    border: 1px solid $color-grey-400
    border-radius: 2px
    padding-top: 30px
    .c3textarea-input
      background-color: inherit
      color: inherit
      border: none
      width: 100%
      height: 100%
      min-width: 100%
      min-height:100px
      max-width: 865px
      max-height:300px
    &.focus
      border: 1px solid $color-blue-500
    &:active:not([disabled]), &.focus:not([disabled])
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
  &-label
    font-size: 14px
    color: $color-grey-400
    background-color: inherit
    left: .4rem
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
    &.focus
      color: $color-blue-500
      font-size: 10px
      left: .5rem
      top: -.4rem
    &[disabled]
      color: $color-grey-500

  &-legend
    margin-left: 8px
    font-size: 12px
    color: $color-grey-400
    &.focus
      color: $color-blue-500
</style>
