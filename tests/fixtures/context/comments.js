// child_process.exec(commentedLine);
/*
child_process.exec(commentedBlock);
*/
function executable(command) {
  child_process.exec(command); // adjacent comment
}
