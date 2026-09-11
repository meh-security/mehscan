using Microsoft.AspNetCore.Mvc;

public class StoredPost
{
    public string Contents { get; set; }
}

public class PostRepository
{
    private dynamic _db;

    public StoredPost CreatePost(string contents)
    {
        var post = new StoredPost { Contents = contents };
        _db.Posts.Add(post);
        return post;
    }
}

public class PostsController : Controller
{
    private PostRepository _repository;

    [HttpPost]
    public IActionResult Create(string contents)
    {
        _repository.CreatePost(contents);
        return Ok();
    }
}

public class StoredComment
{
    public string Contents { get; set; }
}

public class CommentRepository
{
    private dynamic _db;

    public void SaveComment(StoredComment comment)
    {
        _db.Comments.Add(comment);
    }
}

public class CommentsController : Controller
{
    private CommentRepository _repository;

    [HttpPost]
    public IActionResult CreateComment(string contents)
    {
        var comment = new StoredComment { Contents = contents };
        _repository.SaveComment(comment);
        return Ok();
    }
}
