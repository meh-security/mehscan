import { Component } from '@angular/core';

@Component({ template: '<p [innerHTML]="content"></p>' })
export class Ordinary {
  content = '';
}
