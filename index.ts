const express = require('express');
const mongoose = require('mongoose');
const bcrypt  = require('bcrypt');
const jwt = require('jsonwebtoken');


// creating an exprress app
const app = express();
const PORT = 3000;

//connnect to mongodb database
mongoose.connect('mongodb://localhost:27017/myuserapp').then(()=> {
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
    const authheader = req.headers['authorization'];
    if(!authheader){
        return res.status(401).json({error : "Unauthorized"});
    }

    const token = authheader.split(' ')[1]; 

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

app.post('/api/register', async( req:any , res:any ) => {
    try {
        // check if user already exists
        const existingUSer  = await User.findOne({email: req.body.email})

        if(existingUSer){
            return res.status(400).json({error: "User already exists"});
        }

        // hash the password
        const hashedPassword = await bcrypt.hash(req.body.password, 10);

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


// Route to authenticate and log in a user
app.post('/api/login', async (req:any,  res:any) => {
  try {
    // Check if the email exists
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Compare passwords
    const passwordMatch = await bcrypt.compare(req.body.password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Generate JWT token
    const token = jwt.sign({ email: user.email }, 'secret');
    res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ error: 'Internal server error' });
  }
});

// protected route to get user detauls
app.get('/api/user', verifyToken , async (req:any, res:any) => {
    try {
        const user = await User.findOne({email: req.user.email});

        if(!user){
            return res.status(404).json({error: "User not found"});
        }

        res.status(200).json({username: user.username, email: user.email});

    }catch (e:any){
        res.status(500).json({error: e.message});
    }
});


app.get('/',(req:any,res:any) => {
    res.send('Welcome to the User Management API');
});


app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});