const express = require("express");
const mongoose = require("mongoose");
const nodemailer = require("nodemailer");
const User = require("./models/user");
const Todos = require("./models/todo");
const OTP = require("./models/OTP.js");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const app = express();
const cors = require("cors");

// Added dotenv file:

const env = require("dotenv");
env.config();

// Import MiddleWare:
const { checkBodyParams, isLoggedIn } = require("./Middleware/general.js");
const user = require("./models/user");
app.use(express.json());
app.use(cors());

//database connection
mongoose
  .connect(process.env.DATABASE_URL)
  .then(() => console.log("database connected"))
  .catch((err) => console.log("error connecting database", err.message));

//STEP-1: SignUp (POST)
app.post("/auth/signup", checkBodyParams, (req, res) => {
  const { name, email, password } = req.body;

  // If account of this email already exists
  User.findOne({ email: req.body.email })
    .then((user) => {
      // If email exists return the response form here only
      if (user) {
        return res.json({ success: false, message: " Email already in use" });
      }

      // If email is new then first we will hash the password

      bcrypt.hash(password, 10, (err, has) => {
        if (err) return res.json({ success: false, message: err.message });

        //Create user in database

        User.create({ email: email, name: name, password: has })
          .then((user) => {
            // if account is created successfully then sent an account activation email

            // generate token
            const token = jwt.sign({ _id: user._id }, "ABCD");

            //send this token on email
            var transporter = nodemailer.createTransport({
              service: "gmail",
              auth: {
                user: process.env.EMAIL,
                pass: process.env.PASSWORD,
              },
            });

            var mailOptions = {
              from: process.env.EMAIL,
              to: user.email,
              subject: " Activate Your Todo Account",
              html: `
    <p> Hey ${user.name}, Welcome in Todo App. Your Accoun has been created. In order to use youe Account you have to Verify your email by clicking on following link.</p>
    
    <a href="https://todo-application-bdvl.onrender.com/${token}"> Activate Account </a>
    `,
            };
            // sending Mail
            transporter.sendMail(mailOptions, function (error, info) {
              if (error) {
                return res.json({ success: false, message: "Error Occured" });
              } else {
                return res.json({
                  success: true,
                  message:
                    "An Account activation link has been sent on given email.",
                });
              }
            });
          })
          .catch((err) => res.json({ success: false, message: err.message }));
      });
    })
    .catch((err) => res.json({ success: false, message: err.message }));
});

// Route that will handle the account activation link sent to Email

app.get("/auth/activate-account/:token", (req, res) => {
  const Token = req.params.token;

  // try to verify token
  try {
    const data = jwt.verify(Token, "ABCD");
    // Try to find user now
    User.findByIdAndUpdate(data._id, { emailVerified: true })
      .then(() => {
        res.json({ success: true, message: " Now You Can Login" });
      })
      .catch(() => {
        res.json({
          success: false,
          message: "Please Try Again! We are sorry for inconvinece!",
        });
      });
  } catch (err) {
    return res.json({ success: false, message: "Link has been Expired!" });
  }
});

//STEP-2: Login (POST)

app.post("/auth/login", (req, res) => {
  const { email, password } = req.body;

  // check if account exists
  User.findOne({ email: email })
    .then((user) => {
      if (!user) {
        return res.json({ success: false, message: "Email not found!" });
      }
      // if user exists then we will check the email is verified or not
      if (user.emailVerified == false)
        return res.json({
          success: false,
          message: "Please verify your account by the link sent on your mail",
        });
      // if user exists then compare password
      bcrypt.compare(password, user.password, (err, result) => {
        if (result == true) {
          //if password is verified
          //we will sign a token
          const token = jwt.sign(
            { name: user.name, email: user.email, _id: user._id },
            "ABCD"
          );

          return res.json({
            success: true,
            message: "Logged In",
            token: token,
            name: user.name,
          });
        } else {
          return res.json({
            success: false,
            message: "Incorrect password",
          });
        }
      });
    })
    .catch((err) => {
      return res.json({
        success: false,
        message: "An error occurred while processing your request",
      });
    });
});

// LAST STEP-5 - Forgot Password:

// If user forget their password then we have to send OTP to the users email Account
// Route for sending OTP
app.post("/auth/forget-password", async (req, res) => {
  const { email } = req.body;

  try {
    // Find the user by email
    const user = await User.findOne({ email: req.body.email });

    if (user) {
      // Generate a random OTP
      const otp = Math.floor(Math.random() * 100000);

      // Store the OTP in the database
      await OTP.create({
        email: req.body.email,
        otpcode: otp,
      });

      // Send the OTP to the user's email
      const transporter = nodemailer.createTransport({
        service: "gmail",
        auth: {
          user: process.env.EMAIL,
          pass: process.env.PASSWORD,
        },
      });

      const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: "Password Reset OTP",
        text: `Your OTP to reset your password is: ${otp}`,
      };

      await transporter.sendMail(mailOptions);

      return res.json({ success: true, message: "OTP sent to your email" });
    } else {
      // If user does not exist
      return res
        .status(404)
        .json({ success: false, message: "Email not found" });
    }
  } catch (err) {
    console.error(err);
    return res
      .status(500)
      .json({ success: false, message: "An error occurred" });
  }
});

// Assuming you have a route for verifying OTP

app.post("/verify-otp", async (req, res) => {
  const { email, password, otp } = req.body;

  try {
    // Find the stored OTP for the user
    const storedOTP = await OTP.findOne({ email, code: otp });

    if (!storedOTP) {
      return res.status(400).json({ error: "No OTP found for the user" });
    }

    // Check if received OTP matches the stored OTP
    if (otp !== storedOTP.code) {
      return res.status(400).json({ error: "Invalid OTP" });
    }

    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Update user's password with the hashed password
    await User.findOneAndUpdate({ email }, { password: hashedPassword });

    // Optionally, you may want to delete the OTP record from the database after successful verification
    // await OTP.deleteOne({ email, code: otp });

    // If OTP is valid and password , send success response
    res.json({ message: "OTP verified and password updated successfully" });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "An error occurred" });
  }
});

// STEP-3: ADD TODOS ((Needs token else not allowe)

app.post("/todo/add", isLoggedIn, (req, res) => {
  const { title, description } = req.body;

  //First i will verify if user is loggedIn or not
  //user is logged then add todo
  Todos.create({ title, description, createdBy: req.tokenData._id })
    //res.json({ success: true, data: "HI" });
    .then((t) => res.json({ success: true, message: "TODO Added" }))
    .catch((err) => res.json({ success: false, message: err.message }));
});
//STEP-4: (READ TODOS)

app.get("/todo/get", isLoggedIn, (req, res) => {
  // console.log("Controller", req.tokenData);
  Todos.find({ createdBy: req.tokenData._id })
    .then((todo) => res.json({ success: true, todos: todo }))
    .catch((err) => res.json({ success: false, message: err.message }));
});

// MiddleWare: Method that are excuted between route and controller || (MiddleWare have 3 Parameters- req, res, next)

// TIP: Whenever you wanted to design an API where document will be uploaded or delete always specify the _id or      docID in the URL Params of API

app.put("/todo/markAscomplete/:todoId", isLoggedIn, (req, res) => {
  // if we add (:)'colon sign' then place of (todoId) we write anything like:(http://127.0.0.1:3001/todo/update/asdfghj) then we get message ("asdfghj")

  // if we not add (:)'colon sign', then we have to write full API - (http://127.0.0.1:3001/todo/update/todoId)
  //  then we get message ("Hi Nikhil")

  const { completed } = req.body;
  const todoId = req.params.todoId;

  // give me todo with given ID and created by loggedIn user

  Todos.findOneAndUpdate(
    { _id: todoId, createdBy: req.tokenData._id },
    { completed }
  )
    .then((doc) => {
      if (doc) {
        return res.json({ success: true, data: "Todo Updated" });
      } else {
        return res.json({ success: false, data: "No Document Found" });
      }
    })
    .catch((err) => res.json({ success: false, data: err.message }));
});

// Delete Todo
app.delete("/todo/delete/:todoId", isLoggedIn, (req, res) => {
  Todos.findOneAndDelete({
    _id: req.params.todoId,
    createdBy: req.tokenData._id,
  })
    .then((doc) => {
      if (doc) {
        return res.json({ success: true, data: "Document Deleted" });
      } else {
        return res.json({ success: false, data: "No Document Found" });
      }
    })
    .catch((err) => res.json({ success: false, data: err.message }));
});

app.listen(3001, () => console.log("server is running at 3001"));
