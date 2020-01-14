<template>
  <div class="c3gateway">
    <div class="c3gateway-row">
      <span class="c3gateway-title">
        Gateway Selection
      </span>
      <!-- <span class="icon exclamation"></span> -->
    </div>
    <SelectGatewayForm />
  </div>
</template>

<script lang="ts">
import { Component, Mixins } from 'vue-property-decorator';

import C3 from '@/c3';
import SelectGatewayForm from '@/components/form/SelectGatewayForm.vue';

@Component({
  components: {
    SelectGatewayForm
  }
})
export default class GatewayForm extends Mixins(C3) {}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style lang="sass">
@import '~@/scss/colors.scss'
.c3gateway
  display: flex
  flex-direction: column
  flex-shrink: 1
  margin: 40px auto 24px auto
  padding: 0
  width: 100%
  max-width: 1200px
  position: relative
  .icon.exclamation
    position: relative
    &:hover:after
      display: block
      position: absolute
      font-family: "Roboto"
      font-size: 12px
      color: $color-grey-400
      background-color: $color-grey-900
      border-radius: 2px
      width: max-content
      padding: 4px 8px
      top: 30px
      right: 0
      max-width: 400px
      z-index: 9
      content: "TODO: helper text for gateway selection."
  &-row
    display: flex
    padding: 0
    flex-direction: row
    justify-content: space-between
    align-items: center
    height: 32px
    width: 100%
    max-width: 1200px
    &:first-of-type
      margin: 0 0 3px 0
    &:not(:first-of-type)
      margin: 3px 0 3px 0
    &:last-of-type:not(:first-of-type)
      margin: 3px 0 0 0
    &:only-child
      margin: 0
  &-title
    font-family: "Roboto Mono"
    font-weight: 500
    font-size: 18px
    line-height: 25px
    display: flex
    align-items: center
    letter-spacing: -0.05em
    color: $color-grey-400
    margin-bottom: 1rem
</style>
