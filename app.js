const express = require("express");
const app = express();
const csrf = require("tiny-csrf");
const cookieParser = require("cookie-parser");
const { Admin, Election, questions, options, Voters } = require("./models");
const bodyParser = require("body-parser");
const connectEnsureLogin = require("connect-ensure-login");
const LocalStratergy = require("passport-local");
const path = require("path");
const bcrypt = require("bcrypt");
const session = require("express-session");
const passport = require("passport");
// eslint-disable-next-line no-unused-vars
const { AsyncLocalStorage } = require("async_hooks");
const flash = require("connect-flash");
const saltRounds = 10;
app.use(bodyParser.json());
// eslint-disable-next-line no-undef
app.set("views", path.join(__dirname, "views"));
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: false }));
app.use(flash());
app.use(cookieParser("Some secret String"));
app.use(csrf("this_should_be_32_character_long", ["POST", "PUT", "DELETE"]));

app.use(
  session({
    secret: "my-super-secret-key-2837428907583420",
    cookie: {
      maxAge: 60*60*24*1000,
    },
  })
);
app.use((request, response, next) => {
  response.locals.messages = request.flash();
  next();
});
app.use(passport.initialize());
app.use(passport.session());

passport.use(
  "user-local",
  new LocalStratergy(
    {
      usernameField: "email",
      passwordField: "password",
    },
    (username, password, done) => {
      Admin.findOne({ where: { email: username } })
        .then(async (user) => {
          const result = await bcrypt.compare(password, user.password);
          if (result) {
            return done(null, user);
          } else {
            return done(null, false, { message: "incorrect Password!" });
          }
        })
        .catch(() => {
          return done(null, false, { message: "incorrect Email-ID!" });
        });
    }
  )
);
passport.use(
  "voter-local",
  new LocalStratergy(
    {
      usernameField: "voterid",
      passwordField: "password",
    },
    (username, password, done) => {
      Voters.findOne({
        where: { voterid: username },
      })
        .then(async (user) => {
          const result = await bcrypt.compare(password, user.password);
          if (result) {
            return done(null, user);
          } else {
            return done(null, false, { message: "incorrect password" });
          }
        })
        .catch(() => {
          return done(null, false, {message: "incorrect  ID",});
        });
    }
  )
);

app.set("view engine", "ejs");
// eslint-disable-next-line no-undef
app.use(express.static(path.join(__dirname, "public")));
passport.serializeUser((user, done) => {
  done(null, { id: user.id, case: user.case });
});

passport.deserializeUser((id, done) => {
  if (id.case === "admins") {
    Admin.findByPk(id.id)
      .then((user) => {
        done(null, user);
      })
      .catch((error) => {
        done(error, null);
      });
  } else if (id.case === "voters") {
    Voters.findByPk(id.id)
      .then((user) => {
        done(null, user);
      })
      .catch((error) => {
        done(error, null);
      });
  }
});
app.post(
  "/session",
  passport.authenticate("user-local", {
    failureRedirect: "/login",
    failureFlash: true,
  }),
  async (request, response) => {
    return response.redirect("/elections");
  }
);

app.get("/", (request, response) => {
  if (request.user) {
    if (request.user.case === "admins") {
      return response.redirect("/elections");
    } else if (request.user.case === "voters") {
      request.logout((err) => {
        if (err) {
          return response.json(err);
        }
        response.redirect("/");
      });
    }
  } else {
    response.render("index", {
      title: "Voting_app",
    });
  }
});

app.get(
  "/index",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    response.render("index", {
      title: "Voting_app",
      csrfToken: request.csrfToken(),
    });
  }
);

app.get(
  "/elections",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      let user = await Admin.findByPk(request.user.id);
      let loggedinuser = user.dataValues.firstName;
      try {
        const elections_list = await Election.getElections(request.user.id);
        if (request.accepts("html")) {
          response.render("elections", {
            title: "Voting_app",
            userName: loggedinuser,
            elections_list,
          });
        } else {
          return response.json({
            elections_list,
          });
        }
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    } else if (request.user.role === "voter") {
      return response.redirect("/");
    }
  }
);
app.get(
  "/addquestion",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      response.render("newelection", {
        title: "Create New Election",
        csrfToken: request.csrfToken(),
      });
    }
  }
);

app.post(
  "/elections",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      if (request.body.electionName.length === 0) {
        request.flash("error", "Election name can't be empty!");
        return response.redirect("/addquestion");
      }
      if (request.body.publicurl.length === 0) {
        request.flash("error", "Enter the url!!");
        return response.redirect("/addquestion");
      }
      try {
        await Election.addElections({
          electionName: request.body.electionName,
          publicurl: request.body.publicurl,
          adminID: request.user.id,
        });
        return response.redirect("/elections");
      } catch (error) {
        request.flash("error", "The url alredy exists plse choose the different url!!");
        return response.redirect("/addquestion");
      }
    } else if (request.user.role === "voter") {
      return response.redirect("/");
    }
  }
);

app.get("/signup", (request, response) => {
  try {
    response.render("signup", {
      title: "Create  an Admin account",
      csrfToken: request.csrfToken(),
    });
  } catch (err) {
    console.log(err);
  }
});

app.get("/signout", (request, response, next) => {
  request.logout((err) => {
    if (err) {
      return next(err);
    }
    response.redirect("/");
  });
});

app.get("/login", (request, response) => {
  if (request.user) {
    return response.redirect("/elections");
  }
  response.render("login", {
    title: "Admin Login Page",
    csrfToken: request.csrfToken(),
  });
});

app.post("/admin", async (request, response) => {
  if (request.body.email.length == 0) {
    request.flash("error", "Add New Email!!");
    return response.redirect("/signup");
  }
  if (request.body.firstName.length == 0) {
    request.flash("error", "ADD FIRST NAME!!");
    return response.redirect("/signup");
  }
  if (request.body.password.length == 0) {
    request.flash("error", "Enter password!!");
    return response.redirect("/signup");
  }
  if (request.body.password.length <= 5) {
    request.flash("error", "you assword should contain 5 characters");
    return response.redirect("/signup");
  }
  const hashedPwd = await bcrypt.hash(request.body.password, saltRounds);
  try {
    const user = await Admin.create({
      firstName: request.body.firstName,
      lastName: request.body.lastName,
      email: request.body.email,
      password: hashedPwd,
    });
    request.login(user, (err) => {
      if (err) {
        console.log(err);
        response.redirect("/");
      } else {
        response.redirect("/elections");
      }
    });
  } catch (error) {
    console.log(error);
    request.flash("error", "User account already exists please login to your account!!");
    return response.redirect("/signup");
  }
});
app.get(
  "/electionslist/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      try {
        const voter = await Voters.getvoters(request.params.id);
        const question = await questions.getquestion(request.params.id);
        const election = await Election.findByPk(request.params.id);
        // eslint-disable-next-line no-unused-vars
        const electionname = await Election.getElections(
          request.params.id,
          request.user.id
        );
        const countofquestions = await questions.countquestions(
          request.params.id
        );
        const countofvoters = await Voters.countvoters(request.params.id);
        response.render("electionquestion", {
          election: election,
          publicurl: election.publicurl,
          voters: voter,
          questions: question,
          id: request.params.id,
          title: election.electionName,
          countquestions: countofquestions,
          countvoters: countofvoters,
        });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
  }
);
app.get(
  "/questions/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      // eslint-disable-next-line no-unused-vars
      const electionlist = await Election.getElections(
        request.params.id,
        request.user.id
      );
      const questions1 = await questions.getquestions(request.params.id);
      const election = await Election.findByPk(request.params.id);
      if (election.launched) {
        request.flash(
          "error",
          "your election is running !! can't implement your request"
        );
        return response.redirect(`/electionslist/${request.params.id}`);
      }
      if (request.accepts("html")) {
        response.render("questions", {
          title: election.electionName,
          id: request.params.id,
          questions: questions1,
          election: election,
          csrfToken: request.csrfToken(),
        });
      } else {
        return response.json({
          questions1,
        });
      }
    }
  }
);
app.get(
  "/createquestions/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      response.render("questioncreate", {
        id: request.params.id,
        csrfToken: request.csrfToken(),
      });
    }
  }
);

app.post(
  "/createquestions/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      if (!request.body.questionname) {
        request.flash("error", "please enter a question to proceed...!!!");
        return response.redirect(`/createquestions/${request.params.id}`);
      }
      if (request.body.questionname < 5) {
        request.flash("error", "please enter a question name with 5 characters");
        return response.redirect(`/createquestions/${request.params.id}`);
      }
      try {
        const question = await questions.addquestion({
          electionID: request.params.id,
          questionname: request.body.questionname,
          description: request.body.description,
        });
        return response.redirect(
          `/getelections/addoption/${request.params.id}/${question.id}/options`
        );
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
  }
);

app.get(
  "/getelections/addoption/:id/:questionID/options",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      try {
        const question = await questions.getquestion(request.params.questionID);
        const option = await options.retrieveoptions(request.params.questionID);
        if (request.accepts("html")) {
          response.render("addoption", {
            title: question.questionname,
            description: question.description,
            id: request.params.id,
            questionID: request.params.questionID,
            option,
            csrfToken: request.csrfToken(),
          });
        } else {
          return response.json({
            option,
          });
        }
      } catch (err) {
        return response.status(422).json(err);
      }
    }
  }
);

app.delete(
  "/deletequestion/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      try {
        const res = await questions.deletequestion(request.params.id);
        return response.json({ success: res === 1 });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
  }
);

app.post(
  "/getelections/addoption/:id/:questionID/options",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      if (!request.body.optionname) {
        request.flash("error", "Please Enter An Option");
        return response.redirect(
          `/getelections/addoption/${request.params.id}/${request.params.questionID}/options`
        );
      }
      try {
        await options.addoption({
          optionname: request.body.optionname,
          questionID: request.params.questionID,
        });
        return response.redirect(
          `/getelections/addoption/${request.params.id}/${request.params.questionID}/options/`
        );
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
  }
);

app.delete(
  "/:id/deleteoptions",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      try {
        const res = await options.deleteoptions(request.params.id);
        return response.json({ success: res === 1 });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
  }
);
app.get(
  "/elections/:electionID/questions/:questionID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      const adminID = request.user.id;
      const admin = await Admin.findByPk(adminID);
      const election = await Election.findByPk(request.params.electionID);
      const Question = await questions.findByPk(request.params.questionID);
      response.render("editquestion", {
        username: admin.name,
        election: election,
        question: Question,
        csrf: request.csrfToken(),
      });
    }
  }
);
app.post(
  "/elections/:electionID/questions/:questionID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      if (request.body.questionname.length < 3) {
        request.flash("error", "Question name should be atlesat 5 characters!");
        return response.redirect(
          `/elections/${request.params.electionID}/questions/${request.params.questionID}/edit`
        );
      }
      try {
        await questions.editquestion(
          request.body.questionname,
          request.body.description,
          request.params.questionID
        );
        response.redirect(`/questions/${request.params.electionID}`);
      } catch (error) {
        console.log(error);
        return;
      }
    }
  }
);
app.get(
  "/elections/:electionID/questions/:questionID/options/:optionID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      const adminID = request.user.id;
      const admin = await Admin.findByPk(adminID);
      const election = await Election.findByPk(request.params.electionID);
      const Question = await questions.findByPk(request.params.questionID);
      const option = await options.findByPk(request.params.optionID);
      response.render("editoption", {
        username: admin.name,
        election: election,
        question: Question,
        option: option,
        csrf: request.csrfToken(),
      });
    }
  }
);
app.post(
  "/elections/:electionID/questions/:questionID/options/:optionID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      try {
        await options.editoption(
          request.body.optionname,
          request.params.optionID
        );
        response.redirect(
          `/getelections/addoption/${request.params.electionID}/${request.params.questionID}/options`
        );
      } catch (error) {
        console.log(error);
        return;
      }
    }
  }
);
app.get(
  "/voters/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      // eslint-disable-next-line no-unused-vars
      const electionlist = await Election.getElections(
        request.params.id,
        request.user.id
      );
      const voterlist = await Voters.getvoters(request.params.id);
      const election = await Election.findByPk(request.params.id);
      if (request.accepts("html")) {
        response.render("voters", {
          title: election.electionName,
          id: request.params.id,
          voters: voterlist,
          election: election,
          csrfToken: request.csrfToken(),
        });
      } else {
        return response.json({
          voterlist,
        });
      }
    }
  }
);
app.get("/voters/electionslist/:id", async (request, response) => {
  if (request.user.case === "admins") {
    try {
      const electionname = await Election.getElections(
        request.params.id,
        request.user.id
      );
      const countofquestions = await questions.countquestions(
        request.params.id
      );
      const countofvoters = await Voters.countvoters(request.params.id);
      const election = await Election.findByPk(request.params.id);
      response.render("eletionquestion", {
        publicurl: election.publicurl,
        election: election,
        id: request.params.id,
        title: electionname.electionName,
        countquestions: countofquestions,
        countvoters: countofvoters,
      });
    } catch (error) {
      console.log(error);
      return response.status(422).json(error);
    }
  }
});
app.get("/elections/electionslist/:id", async (request, response) => {
  if (request.user.case === "admins") {
    try {
      const election = await Election.getElections(
        request.params.id,
        request.user.id
      );
      const ele = await Election.findByPk(request.params.id);
      const countofquestions = await questions.countquestions(
        request.params.id
      );
      const countofvoters = await Voters.countvoters(request.params.id);
      response.render("electionquestion", {
        id: request.params.id,
        publicurl: ele.publicurl,
        title: election.electionName,
        election: election,
        countquestions: countofquestions,
        countvoters: countofvoters,
      });
    } catch (error) {
      console.log(error);
      return response.status(422).json(error);
    }
  }
});

app.get(
  "/newvoter/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      const voterslist = await Voters.getvoters(request.params.id);
      if (request.accepts("html")) {
        response.render("votercreate", {
          id: request.params.id,
          csrfToken: request.csrfToken({ voterslist }),
        });
      } else {
        return response.json({ voterslist });
      }
    }
  }
);

app.post(
  "/vote/:publicurl",
  passport.authenticate("voter-local", {
    failureFlash: true,
  }),
  async (request, response) => {
    return response.redirect(`/vote/${request.params.publicurl}`);
  }
);

app.post(
  "/newvoter/:id",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      if (request.body.voterid.length == 0) {
        request.flash("error", "Enter  a Voter-to Continue!!");
        return response.redirect(`/newvoter/${request.params.id}`);
      }
      if (request.body.password.length == 0) {
        request.flash("error", "choose your Password with more than 6 characters!");
        return response.redirect(`/newvoter/${request.params.id}`);
      }
      if (request.body.password.length < 6) {
        request.flash("error", "Password should be greater than 6 characters!");
        return response.redirect(`/newvoter/${request.params.id}`);
      }
      const hashedPwd = await bcrypt.hash(request.body.password, saltRounds);
      try {
        await Voters.add(request.body.voterid, hashedPwd, request.params.id);
        return response.redirect(`/voters/${request.params.id}`);
      } catch (error) {
        console.log(error);
        request.flash("error", "Voter ID EXISTS Chose different VoterId!!");
        return response.redirect(`/newvoter/${request.params.id}`);
      }
    }
  }
);

app.get(
  "/elections/:electionID/voter/:voterID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      const election = await Election.findByPk(request.params.electionID);
      const voter = await Voters.findByPk(request.params.voterID);
      response.render("editvoters", {
        election: election,
        voter: voter,
        csrf: request.csrfToken(),
      });
    }
  }
);

app.post(
  "/elections/:electionID/voter/:voterID/edit",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      try {
        await Voters.editpassword(
          request.params.voterID,
          request.body.Voterpassword
        );
        response.redirect(`/voters/${request.params.electionID}`);
      } catch (error) {
        console.log(error);
        return;
      }
    }
  }
);

app.delete(
  "/:id/voterdelete",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      try {
        const res = await Voters.delete(request.params.id);
        return response.json({ success: res === 1 });
      } catch (error) {
        console.log(error);
        return response.status(422).json(error);
      }
    }
  }
);

app.get(
  "/election/:id/launch",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      const question = await questions.findAll({
        where: { electionID: request.params.id },
      });
      if (question.length = 1) {
        request.flash("error", "Please Add One question in  Election Ballot!!");
        return response.redirect(`/electionslist/${request.params.id}`);
      }

      for (let i = 0; i < question.length; i++) {
        const option = await options.retrieveoptions(question[i].id);
        if (option.length <= 3) {
          request.flash("error", "Add Three Options to Question");
          return response.redirect(`/electionslist/${request.params.id}`);
        }
      }

      const voters = await Voters.getvoters(request.params.id);
      if (voters.length <= 5) {
        request.flash("error", "Add atleast 5voters to Continue!!!");
        return response.redirect(`/electionslist/${request.params.id}`);
      }

      try {
        await Election.launch(request.params.id);
        return response.redirect(`/electionslist/${request.params.id}`);
      } catch (error) {
        console.log(error);
        return response.send(error);
      }
    }
  }
);

app.get(
  "/election/:id/previewelection",
  connectEnsureLogin.ensureLoggedIn(),
  async (request, response) => {
    if (request.user.case === "admins") {
      const election = await Election.findByPk(request.params.id);
      const optionsnew = [];
      const question = await questions.getquestions(request.params.id);

      for (let i = 0; i < question.length; i++) {
        const optionlist = await options.retrieveoptions(question[i].id);
        optionsnew.push(optionlist);
      }
      if (election.launched) {
        request.flash("error", "Preview After completation of Election!!");
        return response.redirect(`/electionslist/${request.params.id}`);
      }

      response.render("previewelection", {
        election: election,
        questions: question,
        options: optionsnew,
        csrf: request.csrfToken(),
      });
    }
  }
);

app.get("/externalpage/:publicurl", async (request, response) => {
  try {
    const election = await Election.getElectionurl(request.params.publicurl);
    return response.render("loginvoter", {
      publicurl: election.publicurl,
      csrfToken: request.csrfToken(),
    });
  } catch (error) {
    console.log(error);
    return response.status(422).json(error);
  }
});

app.get("/vote/:publicurl/", async (request, response) => {
  if (request.user === false) {
    request.flash("error", "Please Login to cast your Vote!");
    return response.redirect(`/externalpage/${request.params.publicurl}`);
  }
  const election = await Election.getElectionurl(request.params.publicurl);

  if (request.user.voted && election.launched) {
    return response.redirect(`/vote/${request.params.publicurl}/endpage`);
  }

  try {
    const election = await Election.getElectionurl(request.params.publicurl);
    if (request.user.case === "voters") {
      if (election.launched) {
        const question = await questions.getquestions(election.id);
        let optionsnew = [];
        for (let i = 0; i < question.length; i++) {
          const optionlist = await options.retrieveoptions(question[i].id);
          optionsnew.push(optionlist);
        }
        return response.render("castevote", {
          publicurl: request.params.publicurl,
          id: election.id,
          title: election.electionName,
          electionID: election.id,
          question,
          optionsnew,
          csrfToken: request.csrfToken(),
        });
      } else {
        return response.render("404");
      }
    } else if (request.user.case === "admins") {
      request.flash("error", "You are Admin!!!Can't Vote");
      return response.redirect(`/electionslist/${election.id}`);
    }
  } catch (error) {
    console.log(error);
    return response.status(422).json(error);
  }
});

module.exports = app;
