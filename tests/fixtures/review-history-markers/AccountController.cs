class AccountController {
    [HttpPost("password")]
    public IActionResult ChangePassword(ChangePasswordRequest request) {
        account.UpdatePassword(request.NewPassword);
        return Ok();
    }
}
