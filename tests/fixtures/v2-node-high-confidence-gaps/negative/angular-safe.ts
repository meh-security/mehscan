export class SafeComponent {
  route: any
  feedbackService: any
  productService: any
  output: any

  routeSearch () {
    const queryParam = this.route.snapshot.queryParams.q
    this.output.textContent = queryParam
  }

  loadFeedback () {
    this.feedbackService.find().subscribe((feedbacks: any[]) => {
      this.output.textContent = feedbacks[0].comment
    })
  }

  loadProducts () {
    this.productService.search().subscribe((products: any[]) => {
      this.renderProductDescription(products)
    })
  }

  renderProductDescription (tableData: any[]) {
    for (let i = 0; i < tableData.length; i++) {
      this.output.textContent = tableData[i].description
    }
  }
}
