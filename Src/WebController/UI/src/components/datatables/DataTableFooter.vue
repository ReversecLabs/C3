<template>
  <div class="c3tabfooter">
    <div class="c3tabfooter-info">
      Result: {{ results }}
    </div>
    <div class="c3tabfooter-action">
      Items per page:
      <Select
        v-on:change="changePerPage($event, page)"
        :selected="perPage"
        :options="{'5': '5', '10': '10','25': '25', '50': '50', '100': '100', '1000': 'All'}"
        :border="false"
        style="max-width: 60px; margin-bottom: 0;"
        :up="true"
      />
    </div>
    <div class="c3tabfooter-paginator">
      <span class="c3tabfooter-controll" v-on:click.self="prevPage">
        &lt;&nbsp;&nbsp;
      </span>
      Page: {{ actualPage }} of {{ maxPage }}
      <span class="c3tabfooter-controll" v-on:click.self="nextPage">
        &nbsp;&nbsp;&gt;
      </span>
    </div>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Prop, Watch, Mixins } from 'vue-property-decorator';

import { SetActualPageFn, SetItemPerPageFn } from '@/store/PaginateModule';

import C3 from '@/c3';
import Select from '@/components/form/Select.vue';

const PaginateModule = namespace('paginateModule');

@Component({
  components: {
    Select,
  },
})
export default class DataTableFooter extends Mixins(C3) {
  @Prop() public results!: number;

  @PaginateModule.Getter public getActualPage!: number;
  @PaginateModule.Getter public getItemPerPage!: number;

  @PaginateModule.Mutation public setActualPage!: SetActualPageFn;
  @PaginateModule.Mutation public setItemPerPage!: SetItemPerPageFn;

  public page: string = '5';
  public perPage: string = '5';

  public created(): void {
    this.perPage = '' + this.itemPerPage;
  }

  public changePerPage(perPageCount: string): void {
    this.perPage = perPageCount;
    this.setItemPerPage(+this.perPage);
  }

  public nextPage(): void {
    if (this.actualPage < this.maxPage) {
      this.setActualPage(this.actualPage + 1);
    }
  }

  public prevPage(): void {
    if (this.actualPage > 1) {
      this.setActualPage(this.actualPage - 1);
    }
  }

  get actualPage() {
    return this.getActualPage;
  }

  get itemPerPage() {
    return this.getItemPerPage;
  }

  get maxPage() {
    const maxpage: number = Math.ceil(this.results / this.itemPerPage);
    return maxpage === 0 ? 1 : maxpage;
  }
}
</script>

<!-- Add "scoped" attribute to limit CSS to this component only -->
<style scoped lang="sass">
@import '~@/scss/colors.scss'
.c3tabfooter
  display: flex
  flex-direction: row
  flex-wrap: wrap
  height: 40px
  font-size: 12px
  line-height: 14px
  display: flex
  align-items: center
  color: $color-grey-000
  margin-top: -16px
  &-info
    display: flex
    flex-grow: 1
    height: 32px
    align-items: center
  &-action
    display: flex
    flex-grow: 2
    height: 32px
    align-items: center
  &-perpage
    background-color: transparent
    color: white
    border: transparent
    padding-left: .5rem
    outline: none
    border: none
    width: 60px
    & option
      background-color: $color-grey-c3
      &:checked
        background-color: $color-grey-900
        color: $color-blue-c3
  &-paginator
    display: flex
    flex-grow: 3
    justify-content: flex-end
  &-controll
    font-family: "Roboto Mono"
    font-weight: 500
    cursor: pointer
</style>
