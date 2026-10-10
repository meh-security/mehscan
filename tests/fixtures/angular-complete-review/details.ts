import { Component, inject } from '@angular/core';
import { MAT_DIALOG_DATA } from '@angular/material/dialog';

@Component({template: '<article [innerHTML]="data"></article>'})
export class Details {
  data = inject(MAT_DIALOG_DATA);
}
