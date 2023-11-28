require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
//const GoogleStrategy = require("passport-google-oauth20").Strategy;
//const findOrCreate = require("mongoose-findorcreate");
//const md5 = require("md5");
//const encrypt = require("mongoose-encryption");
//const bcrypt = require("bcrypt");
//const saltRounds = 10;
//const User = require('path-to-your-user-model');


const app = express();

//console.log(process.env.API_KEY);

app.set('view engine', 'ejs');
app.use(express.static("public"));
app.use(bodyParser.urlencoded({
    extended: true
}));

//passport
app.use(session({
    secret: "Our little secret.",
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

const db = mongoose.connect("mongodb://127.0.0.1:27017/mohandb", { useNewUrlParser: true });
db.then(() => {
    console.log("db connected....");
});

//mongoose.set("userCreateIndex", true);

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    //googleId: String
    secret: String
});

//localpassport
userSchema.plugin(passportLocalMongoose);
//google
//userSchema.plugin(findOrCreate);

//userSchema.plugin(encrypt, { secret: process.env.SECRET, encryptedFields: ["password"] });

//const secret = "Thisisourlittlesecret.";
//userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });

const User = mongoose.model("User", userSchema);


//passport
passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());


//google
/*passport.use(new GoogleStrategy({
        clientID: process.env.CLIENT - ID, //GOOGLE_CLIENT_ID,
        clientSecret: process.env.CLIENT - SECRET, //GOOGLE_CLIENT_SECRET,
        callbackURL: "http://localhost:3000/auth/google/secrets", //http://www.example.com/auth/google/callback
        userProfileURL: "http://www.example.com/auth/google/callback"
    },
    function(accessToken, refreshToken, profile, cb) {
        console.log(profile);

        User.findOrCreate({ googleId: profile.id }, function(err, user) {
            return cb(err, user);
        });
    }
));*/


app.get("/", function(req, res) {
    res.render("home");
});

//google
/*app.get("/auth/google",
    passport.authenticate("google", { scope: ['profile'] })
);

app.get("/auth/google/callback",
    passport.authenticate('google', { failureRedirect: '/login' }),
    function(req, res) {
        // Successful authentication, redirect home.
        res.redirect('/secrets');
    });*/

app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});

/*app.get("/secrets", function(req, res) {
    if (req.isAuthenticated()) {
        res.render("secrets");
    } else {
        res.redirect("/login");
    }
});*/

/*app.get("/secrets", function(req, res) {
    User.find({ "secret": { $ne: null } }, function(err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                res.render("secrets", { usersWithSecrets: foundUser })
            }
        }
    });
});*/

app.get("/secrets", function(req, res) {
    User.find({ "secret": { $ne: null } })
        .then(foundUsers => {
            if (foundUsers && foundUsers.length > 0) {
                res.render("secrets", { usersWithSecrets: foundUsers });
            } else {
                res.render("secrets", { usersWithSecrets: [] });
            }
        })
        .catch(err => {
            console.log(err);
            res.status(500).send('Internal Server Error');
        });
});

app.get("/submit", function(req, res) {
    if (req.isAuthenticated()) {
        res.render("submit");
    } else {
        res.redirect("/login");
    }
});

app.post("/submit", function(req, res) {
    if (req.isAuthenticated()) {
        const submittedSecret = req.body.secret;

        console.log(req.user.id);

        User.findById(req.user.id)
            .then((foundUser) => {
                if (foundUser) {
                    foundUser.secret = submittedSecret;
                    return foundUser.save();
                }
            })
            .then(() => {
                res.redirect("/secrets");
            })
            .catch((err) => {
                console.error(err);
                res.status(500).send('Internal Server Error');
            });
    } else {
        // Redirect to login if user is not authenticated
        res.redirect("/login");
    }
});

app.get('/logout', (req, res) => {
    req.logout(function(err) {
        if (err) {
            return next(err);
        }
        // Successful logout, redirect or respond as needed
        res.redirect('/');
    });
});

app.post("/register", function(req, res) {

    User.register({ username: req.body.username }, req.body.password, function(err, user) {
        if (err) {
            console.log(err);
            res.redirect("/register");
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });

});

app.post("/login", function(req, res) {

    const user = new User({
        username: req.body.username,
        password: req.body.password
    });

    req.login(user, function(err) {
        if (err) {
            console.log(err);
        } else {
            passport.authenticate("local")(req, res, function() {
                res.redirect("/secrets");
            });
        }
    });

});





app.listen(3000, function() {
    console.log("Server started on port 3000.");
});



/*app.post("/register", async function(req, res) {
    const newUser = new User({
        email: req.body.username,
        password: md5(req.body.password)
            //password: req.body.password
    });

    try {
        await newUser.save();
        res.render("secrets");
    } catch (error) {
        console.error(error);
        res.status(500).send("Error saving user");
    }
});

app.post("/login", async function(req, res) {
    const username = req.body.username;
    const password = md5(req.body.password);
    //const password = req.body.password;

    try {
        const foundUser = await User.findOne({ email: username });
        if (foundUser && foundUser.password === password) {
            res.render("secrets");
        } else {
            res.render("login");
        }
    } catch (error) {
        console.error(error);
        res.status(500).send("Error finding user");
    }
});

app.get("/secrets", function(req, res) {
    res.render("secrets");
});

app.listen(3000, function() {
    console.log("server started on port 3000.");
});*/







/*
const UserPath = require('path-to-your-user-model');
const User = mongoose.model("User", userSchema);*/
/*
const db = mongoose.connect("mongodb://127.0.0.1:27017/mohandb", { useNewUrlParser: true })
   .then(() => {
      console.log("db connected....");
   })
   .catch((error) => {
      console.error("Error connecting to MongoDB:", error);
   });*/

/*app.post("/register", async function(req, res) {
    try {
        // Hash the password using bcrypt
        const hashedPassword = await bcrypt.hash(req.body.password, saltRounds);

        const newUser = new User({
            email: req.body.username,
            password: hashedPassword
                //password: md5(req.body.password)
                //password: req.body.password
        });
        await newUser.save();
        res.render("secrets");
    } catch (error) {
        console.error(error);
        res.status(500).send("Error saving user");
    }
});


app.post("/login", async function(req, res) {
    const username = req.body.username;
    //const password = md5(req.body.password);
    const password = req.body.password;

    try {
        const foundUser = await User.findOne({ email: username });
        if (foundUser) {
            // Compare the hashed password using bcrypt
            const isPasswordMatch = await bcrypt.compare(password, foundUser.password);

            if (isPasswordMatch) {
                res.render("secrets");
            } else {
                res.render("login");
            }
        } else {
            res.render("login");
        }
    } catch (error) {
        console.error(error);
        res.status(500).send("Error finding user");
    }
});

app.get("/secrets", function(req, res) {
    res.render("secrets");
});

app.listen(3000, function() {
    console.log("server started on port 3000.");
});*/









/*const express = require("express");
const path = require('path');
//const becrypt = require('bcrypt');
const bodyParser = require("body-parser");
const ejs = require("ejs");
//const port = 3000;
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");

const app = express();
app.set('view engine', 'ejs');

//console.log(process.env.API_KEY);

app.use(express.static("public"));
app.use(bodyParser.urlencoded({
    extended: true
}));

const db = mongoose.connect("mongodb://127.0.0.1:27017/mohandb", { useNewUrlparser: true });
db.then(() => {
    console.log("db connected....");
})

//mongoose.connect("mongodb://localhost:27017/userDB", { useNewUrlparser: true });
const userSchema = new mongoose.Schema({
    email: String,
    password: String
});

const secret = "Thisisourlittlesecret.";
userSchema.plugin(encrypt, { secret: secret, encryptedFields: ["password"] });

//const User = new mongoose.model("User", userSchema);
const User = mongoose.model("User", userSchema);

app.get("/", function(req, res) {
    res.render("home");
});

app.get("/login", function(req, res) {
    res.render("login");
});

app.get("/register", function(req, res) {
    res.render("register");
});

app.post("/secrets", function(req, res) {
    res.render("secrets");
});

//app.post("/register", function(req, res) {
app.post("/register", async function(req, res) {
    const newUser = new User({
        email: req.body.username,
        password: req.body.password
    });

    try {
        await newUser.save();
        res.render("secrets");
    } catch (error) {
        console.error(error);
        res.status(500).send("Error saving user");
    }
});

app.post("/login", async function(req, res) {
    const username = req.body.userSchema;
    const password = req.body.password;

    try {
        const foundUser = await User.findOne({ email: username });
        if (foundUser && foundUser.password === password) {
            res.render("secrets");
        } else {
            res.render("login");
        }
    } catch (error) {
        console.error(error);
        res.status(500).send("Error finding user");
    }
});


app.listen(3000, function() {
    //app.listen(port, () => {
    console.log("server started on port 3000.");
});*/

/*newUser.save(function(err) {
        if (err) {
            console.log(err);
        } else {
            res.render("secrets");
        }
    });
});*/

/*app.post("/login", function(req, res) {
    const username = req.body.username;
    const password = req.body.password;

    User.findOne({ email: username }, function(err, foundUser) {
        if (err) {
            console.log(err);
        } else {
            if (foundUser) {
                if (foundUser.password === password) {
                    res.render("secrets");
                }
            }
        }
    });
});*/


//passport install prosa
//npm i passport passport-local passport-local-mongoose express-session