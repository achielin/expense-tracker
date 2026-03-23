const express = require('express')
const mysql = require('mysql2')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
require('dotenv').config()


const app = express()
app.use(express.json())

const db = mysql.createConnection({
    host:process.env.DB_HOST ,
    user:process.env.DB_USER ,
    database:process.env.DB_NAME ,
    password:process.env.DB_PASSWORD  
})

db.connect(err=>{
    if(err)throw err
    console.log('Connected to MySql')
})

app.post('/signup',async(req ,res)=>{

    const {email,password} = req.body

    if(!email || !password){
        return res.status(400).json({message:'Email and password required'})
    }

    try{
        const hashedPassword = await bcrypt.hash(password, 10)

        const query = 'INSERT INTO users(email,password) VALUES(?,?)'

        db.query(query,[email,hashedPassword],(err,result)=>{
            if(err){
                console.log(err)
                return res.status(500).json({message:'Error creating user'})
            }
            res.status(200).json({message:'User created successfully'})
        })
    }catch(err){
        res.status(500).json({message:'Server error'})

    }
})


app.post ('/login', (req,res)=>{
    const {email,password} = req.body

    const query = 'SELECT * FROM users WHERE email =?'

    db.query(query,[email],async(err,results)=>{
        if(err) return res.status(500).json({message:'Server error'})
        if(results.length === 0) return res.status(401).json({message:'Invalid credentials'})

        const user = results[0]
        const match = await bcrypt.compare(password,user.password) //comparing the password entered and the stored password
        if(!match) return res.status(401).json({message:'Invalid credentials'})

        const token = jwt.sign({userId:user.id},process.env.JWT_SECRET || 'secretkey',{expiresIn:'7d'})
        res.json({message:'Login successful',token})
    })
})


app.listen(3000,()=>{
    console.log('Server running')
})