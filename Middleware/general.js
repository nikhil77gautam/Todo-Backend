const jwt = require("jsonwebtoken");

// This middleware will be used for Validating the data will signup

function checkBodyParams (req, res, next) {
  const { email, password, name } = req.body;

  if (!email || !password || !name)
    return res.json({ success: false, message: "Invalid Data" });

  if (password.length < 6)
    return res.json({ success: false, message: "Weak Password" });

  if (name.length <= 1)
    return res.json({ success: false, message: "Invalid Name" });

  if (email.length < 6)
    return res.json({ success: false, message: "Wrong Email" });

  next();
}

// This Middleware you can use in any route where you need only loggedin people

function isLoggedIn(req, res, next) {
  //1. I will verify the token(Token will be present in req.header)
  const token = req.headers.authorization;

  try {
    const data = jwt.verify(token, "ABCD");
    // console.log("Middleware", data);

    // Injecting the data inside the request so that the next controller can acess theis injected data this is methodfor passing the data from Middleware to Controller:
    req.tokenData = data;
    next();

    // After you can write your logic:
  } catch (err) {
    return res.json({ success: false, message: err.message });
  }
}
module.exports = { checkBodyParams, isLoggedIn };
