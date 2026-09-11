def review(value):
    database.safe_query(value)
    local.fetch(value)
    filesystem.safe_open(value)
    sandbox.safe_eval(value)

