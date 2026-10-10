import { Component, inject } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';
import { TextChild } from './children';

@Component({imports: [TextChild], template: '<text-child [markup]="trusted"></text-child>'})
export class TextView {
  sanitizer = inject(DomSanitizer);
  message = new URLSearchParams(window.location.search).get('message') || '';
  trusted = this.sanitizer.bypassSecurityTrustHtml(this.message);
}
