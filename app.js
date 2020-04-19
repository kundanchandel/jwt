var bodyparser      = require("body-parser");
var express         = require("express"); 
var app             = express();
var mongoose        = require("mongoose");
var bcrypt          = require("bcrypt")
var jwt             = require("jsonwebtoken");
var cookieParser    = require("cookie-parser");
var dotenv          = require("dotenv");
dotenv.config()
/*************************************MODELS*************************************/
var User            = require("./models/user");


app.use(bodyparser.urlencoded({extended:true}));
app.set("view engine","ejs");
app.use(cookieParser());

mongoose.connect('mongodb://localhost/jwt',function(err){
if(err) throw err;
console.log("connected to db...");
});


app.get("/",function(req,res){
    res.render("index")
});
app.get("/register",function(req,res){
    res.render("register")
});
app.get("/login",function(req,res){
    res.render("login")
});

app.get("/secret",isLoggedIn,function(req,res){
    res.render("secret")
});

app.post("/register",async function(req,res){
    const salt = await bcrypt.genSalt(10);
    const hashedPassword =await bcrypt.hash(req.body.password,salt)
    var user = new User({username:req.body.username, email:req.body.email, password:hashedPassword});
    user.save()
    res.redirect("/")
});
app.post("/login",async function(req,res){
    const user = await User.findOne({email:req.body.email});
    const validpass =await bcrypt.compare(req.body.password,user.password)
    if(!validpass){
        res.send("Invalid password")
    }else{
        const token = jwt.sign({_id:user._id},process.env.TOKEN_SECRET);
        res.cookie('authToken',token,{
            maxAge:2628000000, //1 month in mili sec
            httpOnly:true
        });
        res.redirect("/");
    }
});

app.get("/logout",isLoggedIn,function(req,res){
    res.cookie('authToken',"",{
        maxAge:-1
    });
    res.redirect("/");
});


function isLoggedIn(req,res,next){
    const token = req.cookies.authToken
    if(!token){
        res.send("access denied");
    }else{
        const verified = jwt.verify(token,process.env.TOKEN_SECRET);
         req.user = verified;
        next()
    }
}

app.listen(8000,function(){
    console.log("serving...");
});