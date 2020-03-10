<template>
  <div class="c3navbar">
    <img class="c3navbar-logo" alt="C3 logo" src="@/assets/logo.svg" />
    <div class="c3navbar-left">
      <span class="c3navbar-left--title">C3</span>
    </div>
  </div>
</template>

<script lang="ts">
import Vue from 'vue';
import { Component } from 'vue-property-decorator';

@Component
export default class Navbar extends Vue {}
</script>

<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3navbar
  background-color: $color-grey-900
  display: flex
  margin: 0
  padding: 16px
  flex-direction: row
  flex-wrap: nowrap
  &-logo
    width: auto
    height: 43px
    &:not(:first-of-type)
      padding-left: 4px
      border-left: 2px solid $color-grey-000
  &-left
    line-height: 43px
    display: flex
    justify-content: flex-end
    flex-grow: 1
    &--title
      padding: 0
      margin: 0
      font-family: "Roboto Mono"
      font-size: 36px
      line-height: 30px
      display: flex
      align-items: center
      text-align: right
      letter-spacing: -0.05em
    &--secondary
      padding: 0
      margin: 0
      font-family: "Roboto Mono"
      font-size: 18px
      line-height: 15px
      display: flex
      align-items: center
      text-align: right
      letter-spacing: -0.05em
      text-transform: uppercase
</style>
