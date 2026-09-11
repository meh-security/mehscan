def review(cursor, query, user_id):
    return cursor.execute(query, (user_id,))
