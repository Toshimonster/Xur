const express       = require("express");
const path          = require("path");
const cookieParser  = require("cookie-parser");
const bodyParser    = require("body-parser");
const auth          = require("./auth");
const dir           = "/xur";
const port          = 3000;

let app = new express();

app.use(dir+"/*", bodyParser.urlencoded({extended:false}));
app.use(dir+"/*", cookieParser());
app.use(dir+"/panel/*", auth.authenticateSecret);
app.post(dir+"/login/auth", auth.authenticate);

app.get(dir+"/login", (req, res) => {
  console.log("hi");
  res.sendFile(path.join(__dirname, "./web/login.html"));
});
app.get(dir+"/panel/*", (req, res) => {
  res.send("Supah Secret");
});
app.get(dir+"/login/invalid", (req, res) => {
  res.send("INVALID!")
})

process.stdin.resume();
process.on('exit', ()=> {
  console.log("Exiting")
  auth.exit()
})

app.listen(port, () => console.log(`Xur listening on port ${port}!`));
console.log(`http://localhost:${port}${dir}/login`)
