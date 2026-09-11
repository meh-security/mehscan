def execute(request, evaluator):
    return evaluator.execute(request.form["code"])
