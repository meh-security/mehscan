def review(cursor, query, url, path, code):
    cursor.execute(query)
    requests.get(url)
    open(path)
    open(path, "w")
    eval(code)

