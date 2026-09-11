function afterReturn(command) {
  return;
  child_process.exec(command);
}

function afterThrow(command) {
  throw new Error("stop");
  child_process.exec(command);
}

function afterTerminatingIf(command, condition) {
  if (condition) {
    return;
  } else {
    throw new Error("stop");
  }
  child_process.exec(command);
}

function afterOneBranch(command, condition) {
  if (condition) {
    return;
  }
  child_process.exec(command);
}

function falseBranch(command) {
  if (false) {
    child_process.exec(command);
  }
}

function trueAlternative(command) {
  if (true) {
    harmless();
  } else {
    child_process.exec(command);
  }
}

function afterContinue(command, items) {
  for (const item of items) {
    continue;
    child_process.exec(command);
  }
}

function afterBreak(command, condition) {
  while (condition) {
    break;
    child_process.exec(command);
  }
}
