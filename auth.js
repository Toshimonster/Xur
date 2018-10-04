const crypto = require("crypto");
const fs = require("fs");
const secretExp = 86400000; /** amount of milliseconds in a day */

let genRandomBytes = (length) => {
  return crypto.randomBytes(Math.ceil(length / 2))
    .toString("hex") /** convert to hexadecimal format */
    .slice(0, length); /** return required number of characters */
};

let sha512 = (password, salt) => {
  let hash = crypto.createHmac("sha512", salt); /** Hashing algorithm sha512 */
  hash.update(password);
  let value = hash.digest("hex");
  return value;
};

let verify = (user = "", pass = "") => {
  user = user.toLowerCase();
  return !(!shadow[user] || shadow[user].hash !== sha512(pass, shadow[user].salt));
};

let verifySecret = (user, secret) => {
  if (user) user.toLowerCase();

  return !(!shadow[user] || !shadow[user].secret || shadow[user].secret !== secret || !(parseInt(shadow[user].exp, 16) > Date.now()));
};

let genUserShadow = (user, pass) => {
  let salt = genRandomBytes(16);
  return {
    hash: sha512(pass, salt),
    salt: salt
  };
};

let genSecret = () => {
  return {
    secret: genRandomBytes(48),
    exp: (Date.now() + secretExp).toString(16)
  };
};

let genUserSecret = (user) => {
  user = user.toLowerCase();
  let sec = genSecret();
  shadow[user].secret = sec.secret;
  shadow[user].exp = sec.exp;
  return sec;
};

let addUserShadow = (user, pass) => {
  shadow[user] = genUserShadow(user, pass);
};

let remUserShadow = (user) => {
  delete shadow[user];
};

let authenticate = (request, response, next) => {
  //let user = auth(request);
  if (!request.body || !verify(request.body.uname, request.body.psw)) {
    //response.set('WWW-Authenticate', 'Basic realm="XurAdmin"');
    return response.redirect("./invalid");
  }
  let secret = genUserSecret(request.body.uname);
  response.cookie("secret", secret.secret, {
    maxAge: secretExp,
    httpOnly: true
  });
  response.cookie("user", request.body.uname, {
    maxAge: secretExp,
    httpOnly: true
  });
  response.redirect("../panel/")
  return next();
};

let authenticateSecret = (request, response, next) => {
  if (!verifySecret(request.cookies.user, request.cookies.secret)) {
    return response.redirect("../login/expire");
  }
  return next();
};

let exit = () => {
  console.log(shadow)
  let string=""
  let keys = Object.keys(shadow)
  Object.values(shadow).forEach((value, index) => {
    string += keys[index] + ":" + value.hash + ":" + value.salt + ":" + value.exp + "\n"
  })
  //fs.writeFileSync("./shadow", "", {encoding: "utf-8"})
}

let shadowTemp = fs.readFileSync("./shadow", "utf-8").split("\n");
let shadow = {};
shadowTemp.forEach((u) => {
  let [name, hash, salt, exp] = u.split(":");
  if (name.length > 0) {
    shadow[name] = {
      hash: hash,
      salt: salt,
      exp: exp
    };
  }
});

module.exports = {
  authenticate: authenticate,
  authenticateSecret: authenticateSecret,
  verify: verify,
  addUserShadow: addUserShadow,
  remUserShadow: remUserShadow,
  exit: exit
};
console.log(verify("Admin", "password"));
