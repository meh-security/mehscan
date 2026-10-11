import { Component, Input, input } from '@angular/core';

@Component({selector: 'html-child', template: '<section [innerHTML]="content()"></section>'})
export class HtmlChild {
  content = input.required<any>({alias: 'markup'});
}

@Component({selector: 'text-child', template: '<section [textContent]="content"></section>'})
export class TextChild {
  @Input('markup') content: any;
}
