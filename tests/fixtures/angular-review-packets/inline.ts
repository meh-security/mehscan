import { Component, inject } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Component({ template: '<article [innerHTML]="render()"></article>' })
export class Inline {
  private sanitizer = inject(DomSanitizer);
  content = '';
  render() {
    return this.sanitizer.bypassSecurityTrustHtml(this.content);
  }
}
