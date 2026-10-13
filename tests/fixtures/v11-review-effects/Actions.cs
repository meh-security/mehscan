using Microsoft.AspNetCore.Mvc;
class ActionsController : ControllerBase {
    private static string password = "initial";
    [HttpPost("reset-simulated")]
    public IActionResult ResetPasswordDemo(string token, string next) {
        return Ok(new { success = true, message = "Password reset" });
    }
    [HttpPost("reset-real")]
    public IActionResult ResetPassword(string token, string next) {
        password = next;
        return Ok(new { success = true });
    }
    [HttpDelete("delete-simulated")]
    public IActionResult DeleteUser(int id) {
        System.Console.WriteLine("Deleted " + id);
        return Ok(new { success = true });
    }
}
