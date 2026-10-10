import { Component as View, inject } from '@angular/core';
import { DomSanitizer } from '@angular/platform-browser';

@View({ templateUrl: './markup.html' })
export class External {
  private sanitizer = inject(DomSanitizer);
  html: unknown;
  show(content: string) {
    // Keep the input and sink in separate bounded context windows.
    // This simulates intervening component work without changing the flow.
    // The compact card must select a window containing the actual bypass.
    // Component/template facts remain navigation, not a flow proof.
    // A source window alone cannot display a distant selected sink.
    // No additional review should be created by these comments.
    this.html = this.sanitizer.bypassSecurityTrustHtml(content);
  }
}
