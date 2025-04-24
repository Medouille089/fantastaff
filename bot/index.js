require("dotenv").config();
const express = require("express");
const session = require("express-session");
const passport = require("passport");
const DiscordStrategy = require("passport-discord").Strategy;
const path = require("path");
const fetch = require("node-fetch");

const app = express();

// Sessions
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

// Init Passport
app.use(passport.initialize());
app.use(passport.session());

// Serialize
passport.serializeUser((user, done) => done(null, user));
passport.deserializeUser((obj, done) => done(null, obj));

// Strategy
passport.use(new DiscordStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: process.env.CALLBACK_URL,
    scope: ['identify', 'guilds', 'guilds.members.read']
}, (accessToken, refreshToken, profile, done) => {
    profile.accessToken = accessToken;
    return done(null, profile);
}));

// Auth routes
app.get("/login", passport.authenticate("discord"));
app.get("/callback", passport.authenticate("discord", { failureRedirect: "/unauthorized" }), (req, res) => {
    res.redirect("/check-role");
});

// Middleware check
function ensureAuth(req, res, next) {
    if (req.isAuthenticated()) return next();
    res.redirect("/login");
}

// Check if user has the role
app.get("/check-role", ensureAuth, async (req, res) => {
    const userId = req.user.id;
    const guildId = process.env.GUILD_ID;
    const roleId = process.env.REQUIRED_ROLE_ID;

    const response = await fetch(`https://discord.com/api/v10/guilds/${guildId}/members/${userId}`, {
        headers: {
            Authorization: `Bot ${process.env.BOT_TOKEN}`
        }
    });

    if (!response.ok) return res.redirect("/unauthorized");

    const data = await response.json();
    const roles = data.roles;

    if (roles.includes(roleId)) {
        res.redirect("/whitelist");
    } else {
        res.redirect("/unauthorized");
    }
});

// Static files
app.use("/public", express.static(path.join(__dirname, "public")));

// Protected route
app.get("/whitelist", ensureAuth, (req, res) => {
    res.sendFile(path.join(__dirname, "public/whitelist.html"));
});

// Unauthorized page
app.get("/unauthorized", (req, res) => {
    res.send("<h1>⛔ Accès refusé</h1><p>Vous ne faites pas partie du staff.</p>");
});

// Start server
app.listen(3000, () => {
    console.log("Serveur lancé sur http://localhost:3000/whitelist");
});
