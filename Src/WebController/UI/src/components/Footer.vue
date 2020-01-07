<template>
  <div class="c3footer">C3 dashboard - Labs</div>
</template>

<script lang="ts">
import Vue from 'vue';
import { Component } from 'vue-property-decorator';

@Component
export default class Footer extends Vue {}
</script>

<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3footer
  font-family: "Roboto Mono"
  font-size: 12px
  line-height: 10px
  min-height: 48px
  display: flex
  flex-direction: row
  flex-grow: 0
  justify-content: center
  align-items: center
  text-align: center
  letter-spacing: 0.2em
  text-transform: uppercase
  color: $color-grey-500
  margin-top: auto
</style>
