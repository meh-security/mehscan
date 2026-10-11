import { Component, inject } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';
import { MatDialog } from '@angular/material/dialog';
import { RawPipe } from './raw.pipe';
import { EscapedPipe } from './escaped.pipe';
import { HtmlChild, TextChild } from './children';
import { Details } from './details';

@Component({
  selector: 'app-root',
  imports: [RawPipe, EscapedPipe, HtmlChild, TextChild],
  template: `<p [innerHTML]="message | raw"></p>
    <p [innerHTML]="message | escaped"></p>
    <html-child [markup]="trusted"></html-child>`
})
export class App {
  sanitizer = inject(DomSanitizer);
  dialog = inject(MatDialog);
  message = new URLSearchParams(window.location.search).get('message') || '';
  trusted = this.sanitizer.bypassSecurityTrustHtml(this.message);

  show() {
    const detail = this.sanitizer.bypassSecurityTrustHtml(this.message);
    this.dialog.open(Details, { data: detail });
  }
}
