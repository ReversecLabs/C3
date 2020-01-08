<template>
  <div class="c3form">
    <component
      v-for="field in argumentsArray"
      :key="field.id"
      :legend="field.name"
      :is="getFieldType(field)"
      v-bind="field"
      :validate="field.validation"
      @change="onChange($event, field.id)"
      :name="field.name"
      :random="field.randomize"
      :value="setDefaultValue(field.name, field.defaultValue)"
      :help="field.description"
      autocomplete="off"
      border="ture"
      :options="field.options"
      :selected="field.selected"
      :feedback="field.feedback"
    >
    </component>
    <component
      v-for="field in argumentObjects"
      :key="field.id"
      :legend="field.name"
      :is="getFieldType(field)"
      :validate="field.validation"
      v-bind="field"
      @change="onChange($event, field.id)"
      :random="field.randomize"
      :name="field.name"
      :value="setDefaultValue(field.name, field.defaultValue)"
      :help="field.description"
      autocomplete="off"
      border="ture"
      :options="field.options"
      :selected="field.selected"
      :feedback="field.feedback"
    >
    </component>
  </div>
</template>

<script lang="ts">
import { namespace } from 'vuex-class';
import { Component, Prop, Watch, Mixins } from 'vue-property-decorator';

import { NodeKlass, C3Node, C3FieldDefault } from '@/types/c3types';
import { GetCapabilityForFn } from '@/store/C3Capability';
import { GetTypeNameForInterfaceFn } from '@/store/C3Capability';

import C3 from '@/c3';
import Input from '@/components/form/Input.vue';
import Select from '@/components/form/Select.vue';
import CheckBox from '@/components/form/CheckBox.vue';
import Textarea from '@/components/form/Textarea.vue';

const C3Capability = namespace('c3Capability');
const C3Module = namespace('c3Module');

@Component({
  components: {
    Input,
    Select,
    Textarea,
    CheckBox
  }
})
export default class GeneralForm extends Mixins(C3) {
  @Prop() public command!: any;
  @Prop() public target!: string;
  @Prop() public klass!: NodeKlass;
  @Prop() public targetId!: string;
  @Prop() public interfaceName!: any;
  @Prop() public options!: C3FieldDefault[];

  public isValid: boolean = false;
  // hold the command argumentum array part
  public argumentsArray: any = [];
  // hold the command argumentum objects outside the array
  public argumentObjects: any = [];

  // get the capability from store
  @C3Capability.Getter public getCapabilityFor!: GetCapabilityForFn;
  @C3Capability.Getter
  public getTypeNameForInterface!: GetTypeNameForInterfaceFn;

  get capability() {
    return this.getCapabilityFor(this.interfaceName, this.klass);
  }

  get hasOptions() {
    if (this.options) {
      return JSON.stringify(this.options) === '{}' ? false : true;
    }
    return false;
  }

  // TODO: add more field type
  public getFieldType(f: any): string {
    switch (f.type) {
      case 'boolean':
        return 'CheckBox';
      case 'base64':
        return 'Textarea';
      case 'base32':
        return 'Textarea';
      case 'binary':
        return 'Textarea';
    }
    return 'Input';
  }

  public onChange(payload: any, id: any) {
    this.isValid = true;
    let index = this.argumentsArray.findIndex((i: any) => {
      return i.id === id;
    });
    if (index > -1) {
      this.argumentsArray[index].value = payload.value;
      this.argumentsArray[index].isValid = payload.valid;
    }
    index = this.argumentObjects.findIndex((i: any) => {
      return i.id === id;
    });
    if (index > -1) {
      this.argumentObjects[index].value = payload.value;
      this.argumentObjects[index].isValid = payload.valid;
    }

    this.emitFormData();
  }

  // emit back the form data
  public emitFormData(): void {
    this.isValid = true;

    const formData = [this.clearArray(this.argumentsArray)];
    this.clearArray(this.argumentObjects).forEach((element: any) => {
      formData.push(element);
    });

    const formIsValid = this.isValid;

    this.$emit('change', {
      data: formData,
      valid: formIsValid
    });
  }

  // populate the argumentsArray and argumentObjects arrays on load
  public mounted(): void {
    this.getCommandFrom();
    this.emitFormData();
  }

  public clearArray(data: any): any {
    const rData: any = [];

    if (data) {
      data.forEach((element: any) => {
        if (!element.isValid) {
          this.isValid = false;
        }

        const t = element.type;
        const n = element.name;
        const v = element.value;

        rData.push({
          type: t,
          name: n,
          value: v
        });
      });
    }

    return rData;
  }

  public getValidationRule(e: any): string {
    let validation: string = '';

    if (!!e.type && e.type === 'ip') {
      validation = 'ip|';
    }
    if (!!e.type && (e.type === 'int16' || e.type === 'uint16')) {
      validation = 'numeric|';
      if (!e.min && e.type === 'uint16') {
        validation = validation + 'min_value:0|';
      }
    }
    if (!!e.type && e.type === 'boolean') {
      validation = '';
    }
    if (!!e.min && parseInt(e.min, 10) > 0) {
      if (!!e.type && e.type === 'string') {
        validation = validation + 'min:' + e.min + '|';
      }
      if (!!e.type && (e.type === 'int16' || e.type === 'uint16')) {
        validation = validation + 'min_value:' + e.min + '|';
      }
      validation = validation + 'required|';
    }
    if (!!e.max && e.min && parseInt(e.max, 10) >= parseInt(e.min, 10)) {
      if (!!e.type && e.type === 'string') {
        validation = validation + 'max:' + e.max + '|';
      }
      if (!!e.type && (e.type === 'int16' || e.type === 'uint16')) {
        validation = validation + 'max_value:' + e.max + '|';
      }
    }
    return validation;
  }

  public getRandomLenght(e: any): number | undefined {
    // If no minimum then dont show the random button.
    if ((e.randomize && e.randomize === true) || e.randomize === 'true') {
      if (e.min && parseInt(e.min, 10) > 0) {
        return parseInt(e.min, 10);
      } else {
        e.randomize = 8;
      }
    }
    return undefined;
  }

  public getCrossArgumentOption(inputId: string): string | boolean {
    const outputId = inputId === 'Input ID' ? 'Output ID' : 'Input ID';

    if (this.hasOptions) {
      const output = this.options.find((item: C3FieldDefault) => {
        return item.name === outputId;
      });
      if (output) {
        return output.value;
      }
    }
    return false;
  }

  public getArgumentOption(input: string): string | boolean {
    if (this.hasOptions) {
      const output = this.options.find((item: C3FieldDefault) => {
        return item.name === input;
      });
      if (output) {
        return output.value;
      }
    }
    return false;
  }

  public setDefaultValue(inputName: string, inputValue: any) {
    const value = inputValue;
    if (this.hasOptions) {
      const newValue = this.options.find(item => {
        return inputName === item.name;
      });
      if (!!newValue) {
        return newValue.value;
      }
    }
    return value;
  }

  public setArgumentData(argument: any): any {
    argument.validation = this.getValidationRule(argument);
    argument.id = Math.random()
      .toString(36)
      .substring(2);
    if (this.getRandomLenght(argument)) {
      argument.randomize = this.getRandomLenght(argument);
    }

    argument.value = {
      value: '',
      valid: false
    };

    return argument;
  }

  // populate the argumentsArray and argumentObjects arrays
  public getCommandFrom(): any {
    if (
      this.capability &&
      this.capability.commands &&
      this.capability.commands.length > 0
    ) {
      const com = this.capability.commands.find((c: any) => {
        return c.name === this.command;
      });
      if (com !== undefined && com.arguments) {
        this.argumentsArray = [];
        this.argumentObjects = [];
        com.arguments.forEach((argument: any) => {
          if (Array.isArray(argument)) {
            argument.forEach((argumentItem: any) => {
              argumentItem = this.setArgumentData(argumentItem);
            });
            this.argumentsArray = argument;
          } else {
            argument = this.setArgumentData(argument);
            this.argumentObjects.push(argument);
          }
        });
      } else {
        this.addNotify({
          type: 'info',
          message: "Command not set up correctly, Form can't be generated."
        });
      }
    }
    return false;
  }
}
</script>

<style lang="sass">
@import '~@/scss/colors.scss'
.c3form
  margin-bottom: 16px
</style>
