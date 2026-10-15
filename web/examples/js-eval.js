// JavaScript: eval and file path from user input (hand-written example, never executed)
const fs = require("fs");

function calculate(expression) {
  return eval(expression);
}

function readUpload(req, res) {
  const name = req.query.file;
  fs.readFile("/srv/uploads/" + name, (err, data) => res.send(data));
}
