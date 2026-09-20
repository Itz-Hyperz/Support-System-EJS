// Basic Imports
const config = require("./config.json");
const express = require("express");
const app = express();
const chalk = require('chalk');
const utils = require('hyperz-utils');
const bcrypt = require('bcrypt');
const fs = require('node:fs');

// MySQL Setup
const mysql = require('mysql');
config.sql.charset = "utf8mb4";
let con = mysql.createConnection(config.sql); // set = 0 to disable

// Backend Initialization
const backend = require('./backend.js');
backend.init(app, con);

// Passport Initialization
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
passport.serializeUser(function(user, done) { done(null, user) });
passport.deserializeUser(function(obj, done) { done(null, obj) });
passport.use(new LocalStrategy({ usernameField: 'email' }, backend.authenticateUserLocal))

if(config.discord.enabled) {
    const DiscordStrategy = require('passport-discord-hyperz').Strategy;
    passport.use(new DiscordStrategy({
        clientID: config.discord.oauthId,
        clientSecret: config.discord.oauthToken,
        callbackURL: `${(config.domain.endsWith('/') ? config.domain.slice(0, -1) : config.domain)}/auth/discord/callback`, // THIS IS THE CALLBACK URL
        scope: ['identify', 'guilds', 'email'],
        prompt: 'consent'
    }, function(accessToken, refreshToken, profile, done) {
        process.nextTick(function() {
            return done(null, profile);
        });
    }));
    app.get('/auth/discord', passport.authenticate('discord'));
    app.get('/auth/discord/callback', passport.authenticate('discord', {failureRedirect: '/'}), async function(req, res) {
        req.session?.loginRef ? res.redirect(req.session.loginRef) : res.redirect('/');
        delete req.session?.loginRef
    });
};

// Routing
app.get('', async function(req, res) {
    await backend.resetAppLocals(app);
    let stats = {};
    con.query(`SELECT * FROM tickets`, function(err, row) {
        if(err) throw err;
        stats.tickets = row.length.toLocaleString() || 0;
        con.query(`SELECT * FROM users`, function(err, row) {
            if(err) throw err;
            stats.users = row.length.toLocaleString() || 0;
            con.query(`SELECT * FROM staff`, function(err, row) {
                if(err) throw err;
                stats.staff = row.length.toLocaleString() || 0;
                con.query(`SELECT * FROM categories`, function(err, row) {
                    if(err) throw err;
                    stats.categories = row.length.toLocaleString() || 0;
                    let isStaff = false;
                    if(req.isAuthenticated()) {
                        con.query(`SELECT * FROM staff WHERE userid="${req.user.id}"`, function(err, row) {
                            if(err) throw err;
                            if(row[0]) isStaff = true;
                            res.render('index.ejs', { stats: stats, isStaff: isStaff, loggedIn: req.isAuthenticated() });
                        });
                    } else {
                        res.render('index.ejs', { stats: stats, isStaff: isStaff, loggedIn: req.isAuthenticated() });
                    };
                });
            });
        });
    });
});

app.get('/login', backend.checkNotAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    res.render('login.ejs', { loggedIn: req.isAuthenticated() });
});

app.get('/cookies', async function(req, res) {
    await backend.resetAppLocals(app);
    res.render('cookies.ejs', { loggedIn: req.isAuthenticated() });
});

app.get('/privacy', async function(req, res) {
    await backend.resetAppLocals(app);
    res.render('privacy.ejs', { loggedIn: req.isAuthenticated() });
});

app.get('/account', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    let isStaff = false;
    con.query(`SELECT * FROM staff WHERE userid="${req.user.id}"`, function(err, row) {
        if(err) throw err;
        if(row[0]) isStaff = true;
        res.render('account.ejs', { user: req.user, isStaff: isStaff, loggedIn: req.isAuthenticated() });
    });
});

app.get('/tickets', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    let isStaff = false;
    con.query(`SELECT * FROM staff WHERE userid="${req.user.id}"`, function(err, row) {
        if(err) throw err;
        if(row[0]) isStaff = true;
        con.query(`SELECT * FROM tickets WHERE userid="${req.user.id}"`, function(err, row) {
            if(err) throw err;
            res.render('tickets.ejs', { loggedIn: req.isAuthenticated(), tickets: row, isStaff: isStaff });
        });
    });
});

app.get('/create', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    let isStaff = false;
    con.query(`SELECT * FROM staff WHERE userid="${req.user.id}"`, function(err, row) {
        if(err) throw err;
        if(row[0]) isStaff = true;
        con.query(`SELECT * FROM categories`, function(err, categories) {
            if(err) throw err;
            res.render('create.ejs', { categories: categories, loggedIn: req.isAuthenticated(), isStaff: isStaff });
        });
    });
});

app.get('/ticket/:uniqueid', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    for(let name of Object.keys(req.params)) {
        req.params[name] = await utils.sanitize(req.params[name]);
        if(req.params[name] == '') req.params[name] = "NA";
    };
    let isAllowed = false;
    let isStaff = false;
    con.query(`SELECT * FROM staff WHERE userid="${req.user.id}"`, function(err, row) {
        if(err) throw err;
        if(row[0]) {
            isAllowed = true;
            isStaff = true;
        };
        con.query(`SELECT * FROM tickets WHERE id="${req.params.uniqueid}"`, async function(err, row) {
            if(err) throw err;
            if(!row[0]) res.redirect('/404');
            if(row[0].userid == req.user.id) isAllowed = true;
            if(!isAllowed) return res.redirect('/404');
            row[0].content = await utils.mdConvert(row[0].content);
            con.query(`SELECT * FROM comments WHERE ticketid="${req.params.uniqueid}"`, async function(err, comments) {
                if(err) throw err;
                let newComments = [];
                for(let item of comments) {
                    item.content = await utils.mdConvert(item.content);
                    newComments.push(item);
                };
                res.render('ticket.ejs', { user: req.user, ticket: row[0], isStaff: isStaff, comments: newComments, loggedIn: req.isAuthenticated() });
            });
        });
    });
});

app.get('/admin', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    con.query(`SELECT * FROM staff WHERE userid="${req.user.id}"`, function(err, row) {
        if(err) throw err;
        if(!row[0]) return res.redirect('/');
        con.query(`SELECT * FROM users`, function(err, users) {
            if(err) throw err;
            con.query(`SELECT * FROM categories`, function(err, categories) {
                if(err) throw err;
                con.query(`SELECT * FROM tickets`, function(err, tickets) {
                    if(err) throw err;
                    con.query(`SELECT * FROM staff`, function(err, staff) {
                        if(err) throw err;
                        res.render('admin.ejs', { isStaff: true, users: users, categories: categories, tickets: tickets, staff: staff, loggedIn: req.isAuthenticated() });
                    });
                });
            });
        });
    });
});

app.get('/backend/delete/user/:uniqueid', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    for(let name of Object.keys(req.params)) {
        req.params[name] = await utils.sanitize(req.params[name]);
        if(req.params[name] == '') req.params[name] = "NA";
    };
    con.query(`SELECT * FROM staff WHERE userid="${req.user.id}"`, function(err, row) {
        if(err) throw err;
        if(!row[0]) return res.redirect('/');
        con.query(`DELETE FROM users WHERE id="${req.params.uniqueid}"`, function(err, row) {
            if(err) throw err;
            return res.redirect('/admin');
        });
    });
});

app.get('/backend/delete/category/:uniqueid', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    for(let name of Object.keys(req.params)) {
        req.params[name] = await utils.sanitize(req.params[name]);
        if(req.params[name] == '') req.params[name] = "NA";
    };
    con.query(`SELECT * FROM staff WHERE userid="${req.user.id}"`, function(err, row) {
        if(err) throw err;
        if(!row[0]) return res.redirect('/');
        con.query(`DELETE FROM categories WHERE id="${req.params.uniqueid}"`, function(err, row) {
            if(err) throw err;
            return res.redirect('/admin');
        });
    });
});

app.get('/backend/delete/ticket/:uniqueid', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    for(let name of Object.keys(req.params)) {
        req.params[name] = await utils.sanitize(req.params[name]);
        if(req.params[name] == '') req.params[name] = "NA";
    };
    con.query(`SELECT * FROM staff WHERE userid="${req.user.id}"`, function(err, row) {
        if(err) throw err;
        if(!row[0]) return res.redirect('/');
        con.query(`DELETE FROM tickets WHERE id="${req.params.uniqueid}"`, function(err, row) {
            if(err) throw err;
            con.query(`DELETE FROM comments WHERE ticketid="${req.params.uniqueid}"`, function(err, row) {
                if(err) throw err;
                return res.redirect('/admin');
            });
        });
    });
});

app.get('/backend/delete/comment/:ticketid/:uniqueid', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    for(let name of Object.keys(req.params)) {
        req.params[name] = await utils.sanitize(req.params[name]);
        if(req.params[name] == '') req.params[name] = "NA";
    };
    con.query(`SELECT * FROM staff WHERE userid="${req.user.id}"`, function(err, row) {
        if(err) throw err;
        if(!row[0]) return res.redirect('/');
        con.query(`DELETE FROM comments WHERE id="${req.params.uniqueid}" AND ticketid="${req.params.ticketid}"`, function(err, row) {
            if(err) throw err;
            return res.redirect(`/ticket/${req.params.ticketid}`);
        });
    });
});

app.get('/backend/markanswer/:ticketid/:commentid', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    for(let name of Object.keys(req.params)) {
        req.params[name] = await utils.sanitize(req.params[name]);
        if(req.params[name] == '') req.params[name] = "NA";
    };
    con.query(`SELECT * FROM staff WHERE userid="${req.user.id}"`, function(err, row) {
        if(err) throw err;
        if(row[0]) isAllowed = true;
        con.query(`SELECT * FROM tickets WHERE id="${req.params.ticketid}"`, async function(err, row) {
            if(err) throw err;
            if(!row[0]) res.redirect('/404');
            if(row[0].userid == req.user.id) isAllowed = true;
            if(!isAllowed) return res.redirect('/404');
            con.query(`UPDATE tickets SET answerid="${req.params.commentid}" WHERE id="${req.params.ticketid}"`, function(err, row) {
                if(err) throw err;
                return res.redirect(`/ticket/${req.params.ticketid}`);
            });
        });
    });
});

app.get('/backend/delete/staff/:uniqueid', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    for(let name of Object.keys(req.params)) {
        req.params[name] = await utils.sanitize(req.params[name]);
        if(req.params[name] == '') req.params[name] = "NA";
    };
    if(!config.ownerIds.includes(req.user.id)) return res.redirect('/');
    con.query(`DELETE FROM staff WHERE userid="${req.params.uniqueid}"`, function(err, row) {
        if(err) throw err;
        return res.redirect('/admin');
    });
});

app.post('/backend/create/category', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    for(let name of Object.keys(req.body)) {
        req.body[name] = await utils.sanitize(req.body[name]);
    };
    let uniqueid = Date.now();
    con.query(`SELECT * FROM staff WHERE userid="${req.user.id}"`, function(err, row) {
        if(err) throw err;
        if(!row[0]) return res.redirect('/');
        con.query(`INSERT INTO categories (id, name) VALUES ("${uniqueid}", "${req.body.name}")`, function(err, row) {
            if(err) throw err;
            res.redirect('/admin');
        });
        if(req.files[0] && req.files[0].originalname.split('.').reverse()[0] == 'png') {
            fs.writeFileSync(`./public/images/category_${uniqueid}.png`, req.files[0].buffer);
        };
    });
});

app.post('/backend/create/ticket', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    for(let name of Object.keys(req.body)) {
        req.body[name] = await utils.sanitize(req.body[name]);
    };
    let uniqueid = (Date.now()).toString();
    con.query(`INSERT INTO tickets (id, userid, username, category, title, content, datecreated, answerid) VALUES ("${uniqueid}", "${req.user.id}", "${req.user.username}", "${req.body.category}", "${req.body.title}", "${req.body.content}", "${await utils.fetchTime(config.timeZone.tz, config.timeZone.format)}", "na")`, function(err, row) {
        if(err) throw err;
        res.redirect(`/ticket/${uniqueid}`);
    });
});

app.post('/backend/create/comment/:ticketid', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    for(let name of Object.keys(req.params)) {
        req.params[name] = await utils.sanitize(req.params[name]);
        if(req.params[name] == '') req.params[name] = "NA";
    };
    for(let name of Object.keys(req.body)) {
        req.body[name] = await utils.sanitize(req.body[name]);
    };
    let uniqueid = (Date.now()).toString();
    con.query(`INSERT INTO comments (id, ticketid, userid, username, content, datecreated) VALUES ("${uniqueid}", "${req.params.ticketid}", "${req.user.id}", "${req.user.username}", "${req.body.content}", "${await utils.fetchTime(config.timeZone.tz, config.timeZone.format)}")`, function(err, row) {
        if(err) throw err;
        res.redirect(`/ticket/${req.params.ticketid}`)
    });
});

app.post('/backend/create/staff', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    for(let name of Object.keys(req.body)) {
        req.body[name] = await utils.sanitize(req.body[name]);
    };
    if(!config.ownerIds.includes(req.user.id)) return res.redirect('/');
    con.query(`INSERT INTO staff (userid) VALUES ("${req.body.userid}")`, function(err, row) {
        if(err) throw err;
        res.redirect('/admin');
    });
});

app.post('/backend/update/settings', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    for(let name of Object.keys(req.body)) {
        req.body[name] = await utils.sanitize(req.body[name]);
    };
    con.query(`SELECT * FROM staff WHERE userid="${req.user.id}"`, function(err, row) {
        if(err) throw err;
        if(!row[0]) return res.redirect('/');
        con.query(`UPDATE sitesettings SET sitename="${req.body.sitename}", sitedesc="${req.body.sitedesc}", sitecolor="${req.body.sitecolor}"`, function(err, row) {
            if(err) throw err;
            res.redirect('/admin');
        });
        if(req.files[0] && req.files[0].originalname.split('.').reverse()[0] == 'png') {
            fs.writeFileSync('./public/assets/logo.png', req.files[0].buffer);
        };
    });
});

app.get('/logout', async function(req, res) {
    await backend.resetAppLocals(app);
    req.logout(function(err) {
        if(err) console.log(err);
    });
    return res.redirect('/');
});

app.post('/register', backend.checkNotAuth, async (req, res) => {
    await backend.resetAppLocals(app);
    for(let name of Object.keys(req.body)) {
        req.body[name] = await utils.sanitize(req.body[name]);
    };
    try {
        let userid = await backend.generateUserId(7);
        let hashedPassword = await bcrypt.hash(req.body.password, 13);
        con.query(`SELECT * FROM users WHERE email="${req.body.email}"`, async function (err, row) {
            if(err) throw err;
            if(!row[0]) {
                con.query(`SELECT * FROM sitesettings`, async function(err, row) {
                    if(err) throw err;
                    if(!row[0]) return console.log('No site settings found.');
                    con.query(`INSERT INTO users (id, username, email, password) VALUES ("${userid}", "${req.body.username}", "${req.body.email}", "${hashedPassword}")`, async function (err, row) {
                        if(err) throw err;
                    });
                    res.redirect('/login')
                });
                if(req.files[0] && req.files[0].originalname.split('.').reverse()[0] == 'png') {
                    fs.writeFileSync(`./public/images/avatar_${userid}.png`, req.files[0].buffer);
                } else {
                    fs.copyFileSync('./public/assets/noavatar.png', `./public/images/avatar_${userid}.png`);
                };
            } else {
                res.redirect('/login')
            };
        });
    } catch {
        res.redirect('/register')
    };
});

app.post('/backend/update/password', backend.checkAuth, async function(req, res) {
    await backend.resetAppLocals(app);
    if(req.body.password !== req.body.confpassword) return res.send('Your passwords do not match...');
    let hashedPassword = await bcrypt.hash(req.body.confpassword, 13);
    con.query(`SELECT * FROM users WHERE id="${req.user.id}"`, async function(err, row) {
        if(err) throw err;
        con.query(`UPDATE users SET password="${hashedPassword}" WHERE id="${req.user.id}"`, function(err, row) { if(err) throw err; });
        req.logout(function(err) {
            if(err) { return next(err); }
        });
        res.redirect('/login');
    });
});

app.post('/auth/local', backend.checkNotAuth, passport.authenticate('local', {
    successRedirect: '/account',
    failureRedirect: '/login',
    failureFlash: true
}));

config.ownerIds.forEach(function(item) {
    if(item != 'YOUR_USER_ID') {
        con.query(`SELECT * FROM staff WHERE userid="${item}"`, function(err, row) {
            if(err) throw err;
            if(!row[0]) {
                con.query(`INSERT INTO staff (userid) VALUES ("${item}")`, function(err, row) {
                    if(err) throw err;
                });
            };
        });
    };
});

// MAKE SURE THIS IS LAST FOR 404 PAGE REDIRECT
app.get('*', function(req, res){
    res.render('404.ejs');
});

// Server Initialization
app.listen(config.port)

// Rejection Handler
process.on('unhandledRejection', (err) => { 
    if(config.debugMode) console.log(chalk.red(err));
});
