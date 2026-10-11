import { Pipe, inject } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Pipe({name: 'escaped'})
export class EscapedPipe {
  sanitizer = inject(DomSanitizer);
  transform(value: string) {
    const text = value.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    return this.sanitizer.bypassSecurityTrustHtml(text);
  }
}
