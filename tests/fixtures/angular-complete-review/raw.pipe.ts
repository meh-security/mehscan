import { Pipe, inject } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@Pipe({name: 'raw'})
export class RawPipe {
  sanitizer = inject(DomSanitizer);
  transform(value: string) {
    return this.sanitizer.bypassSecurityTrustHtml(value);
  }
}
