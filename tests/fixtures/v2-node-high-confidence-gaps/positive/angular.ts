export class SearchComponent {
  route: any
  sanitizer: any
  feedbackService: any
  productService: any
  searchValue: any
  feedback: any

  routeSearch () {
    let queryParam = this.route.snapshot.queryParams.q
    queryParam = queryParam.trim()
    this.searchValue = this.sanitizer.bypassSecurityTrustHtml(queryParam)
  }

  loadFeedback () {
    this.feedbackService.find().subscribe({
      next: (feedbacks: any[]) => {
        this.feedback = this.sanitizer.bypassSecurityTrustHtml(feedbacks[0].comment)
      }
    })
  }

  loadProducts () {
    this.productService.search().subscribe((products: any[]) => {
      this.trustProductDescription(products)
    })
  }

  trustProductDescription (tableData: any[]) {
    for (let i = 0; i < tableData.length; i++) {
      tableData[i].description = this.sanitizer.bypassSecurityTrustHtml(tableData[i].description)
    }
  }
}
