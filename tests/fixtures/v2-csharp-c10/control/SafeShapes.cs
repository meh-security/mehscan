using Microsoft.AspNetCore.Mvc;

public class DisplayModel
{
    public string Contents { get; set; }
}

public class DisplayRepository
{
    private dynamic _db;

    public void Save()
    {
        var trusted = "fixed";
        var model = new DisplayModel { Contents = trusted };
        _db.Displays.Add(model);
    }
}

public class Article
{
    public string Contents { get; set; }
}

public class FirstArticleRepository
{
    private dynamic _db;

    public Article CreateArticle(string contents)
    {
        var article = new Article { Contents = contents };
        _db.Articles.Add(article);
        return article;
    }
}

public class SecondArticleRepository
{
    private dynamic _db;

    public Article CreateArticle(string contents)
    {
        var article = new Article { Contents = contents };
        _db.Archive.Add(article);
        return article;
    }
}

public class ArticlesController : Controller
{
    [HttpPost]
    public IActionResult Create(string contents)
    {
        new FirstArticleRepository().CreateArticle(contents);
        return Ok();
    }
}
