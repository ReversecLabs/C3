import { Prop, Component } from 'vue-property-decorator';
import Vue from 'vue';

/**
 * Shared Class for CheckBox, Input, Textarea and Toggle
 *
 * @export
 * @class C3FormElement
 * @extends {Vue}
 */

@Component
export default class C3FormElement extends Vue {
  @Prop() public help!: string;
  @Prop() public name!: string;
  @Prop() public legend!: string;
  @Prop() public disabled!: boolean;
  @Prop() public autocomplete!: string;

  get hasHelp() {
    return !!this.help;
  }

  get isDisabled() {
    return !!this.disabled;
  }

  get inputUID() {
    return !!this.name
      ? this.name
      : Math.random()
          .toString(36)
          .substring(2);
  }
}
