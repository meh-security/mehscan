const PREFIX = "safe/";
const COMMAND = PREFIX + "tool";
const ENABLED = false;

function review(dynamicCommand) {
  child_process.exec(COMMAND);
  child_process.exec("fixed");
  child_process.exec(`prefix/${dynamicCommand}/suffix`);
  child_process.exec(dynamicCommand);
  eval(true);
  eval(7);
  eval(-7);
  eval(null);
  if (ENABLED) {
    child_process.exec("dead");
  }
}
