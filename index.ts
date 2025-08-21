const express = require('express');
const mongoose = require('mongoose');
const bycrypt  = require('bcrypt');
const jwt = require('jsonwebtoken');


// creating an exprress app
const app = express();
const PORT = 3000;

//connnect to mongodb database
mongoose.connect('mongodb://localhost:27017/myapp').then(()=> {
    console.log('Connected to MongoDB');
}).catch((err:any) => {
    console.error('Error connecting to MongoDB:', err);
});

// define a user schema

const userSchema =  new mongoose.Schema({
    username: String,
    email: String,
    password: String
});


// create a use model
const User = mongoose.model('User', userSchema);


// middleware to parse JSON bodies
app.use(express.json());


// middleware to authenticate JWT tokens
const verifyToken = (req: any, res: any, next: any) => {
    const token = req.headers['authorization'];
    if(!token){
        return res.status(401).json({error : "Unauthorized"});
    }

    jwt.verify(token,'secret',(err:any, decoded:any) => {
        if(err){
            return res.status(401).json(
                {error: "Unauthorized"}
            )
        }

        req.user  =decoded;
        next();
    });
};

// router to register a new user

app.post('/register', async( req:any , res:any ) => {
    try {
        // check if user already exists
        const existingUSer  = await User.findOne({email: req.body.email})

        if(existingUSer){
            return res.status(400).json({error: "User already exists"});
        }

        // hash the password
        const hashedPassword = await bycrypt.hash(req.body.password, 10);

        //create a new user
        const user = new User({
            username : req.body.username,
            email: req.body.email,
            password: hashedPassword
        });

        await user.save();
        res.status(201).json({message: "User registered successfully"});
    }catch (error:any) {
        res.status(500).json({error: error.message});
    }
});