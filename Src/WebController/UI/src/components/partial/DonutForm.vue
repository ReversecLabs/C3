<template>
  <div class="donut-form">
    <h1>Add Command</h1>
    <Select
      legend="Format"
      class="form-element line"
      :selected="selectedFormat"
      :options="{
        Binary: 'Binary',
        Base64: 'Base64',
        Ruby: 'Ruby',
        C: 'C',
        Python: 'Python',
        Powershell: 'Powershell',
        Csharp: 'Csharp',
        HeX: 'HeX'
      }"
      :border="true"
      @change="changeFormat($event, format)"
    />
    <Select
      legend="Compress"
      class="form-element half-line"
      :selected="selectedCompress"
      :options="{
        None: 'None',
	Aplib: 'aPLib',
        Lznt1: 'Lznt1',
        Xpress: 'Xpress',
        Xpress_huff: 'Xpress_huff'
      }"
      :border="true"
      @change="changeCompress($event, compress)"
    />
    <Select
      legend="Entropy"
      class="form-element half-line"
      :selected="selectedEntropy"
      :options="{
        None: 'None',
        Random: 'Random',
        Default: 'Default'
      }"
      :border="true"
      @change="changeEntropy($event, entropy)"
    />
    <Select
      legend="ExitOpt"
      class="form-element half-line"
      :selected="selectedExitOpt"
      :options="{
        Exit_thread: 'Exit_thread',
        Exit_process: 'Exit_process'
      }"
      :border="true"
      @change="changeExitOpt($event, exitOpt)"
    />
    <Select
      legend="Bypass"
      class="form-element half-line"
      :selected="selectedBypass"
      :options="{
        None: 'None',
        Abort: 'Abort',
        Continue: 'Continue'
      }"
      :border="true"
      @change="changeBypass($event, bypass)"
    />
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Prop, Vue } from 'vue-property-decorator';

import C3 from '@/c3';
import Select from '../form/Select.vue';

@Component({
  components: {
    Select
  }
})
export default class DonutForm extends Vue {
  public format: string = 'Binary';
  public compress: string = 'None';
  public entropy: string = 'Default';
  public exitOpt: string = 'Exit_thread';
  public bypass: string = 'None';

  get selectedFormat() {
    return this.format;
  }

  public changeFormat(a: string): void {
    this.format = a;
    this.emitDonut();
  }

  get selectedCompress() {
    return this.compress;
  }

  public changeCompress(a: string): void {
    this.compress = a;
    this.emitDonut();
  }

  get selectedEntropy() {
    return this.entropy;
  }

  public changeEntropy(a: string): void {
    this.entropy = a;
    this.emitDonut();
  }

  get selectedExitOpt() {
    return this.exitOpt;
  }

  public changeExitOpt(a: string): void {
    this.exitOpt = a;
    this.emitDonut();
  }

  get selectedBypass() {
    return this.bypass;
  }

  public changeBypass(a: string): void {
    this.bypass = a;
    this.emitDonut();
  }

  public emitDonut(): void {
    const donut = {
      format: this.format.toUpperCase(),
      compress: this.compress.toUpperCase(),
      entropy: this.entropy.toUpperCase(),
      exitOpt: this.exitOpt.toUpperCase(),
      bypass: this.bypass.toUpperCase()
    };

    this.$emit('change', donut);
  }

  public mounted(): void {
    this.emitDonut();
  }
}
</script>

<style scoped lang="sass">
@import '~@/scss/colors.scss'
.donut-form
  display: flex
  flex-wrap: wrap
  justify-content: space-between
  h1
    width: 100%
  .line
    width: 100%
  .half-line
    max-width: 48%
    width: 48%
</style>
