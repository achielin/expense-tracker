const express = require('express')
const mysql = require('mysql2')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
require('dotenv').config()

const authenticate = require('./middleware/auth')


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

app.post('/expenses', authenticate, (req, res) => {

  const { amount, category, description, date } = req.body;

  if (!amount || !category || !date) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  
  const query = `
    INSERT INTO expenses (user_id, amount, category, description, date)
    VALUES (?, ?, ?, ?, ?)
  `;

  db.query(
    query,
    [req.userId, amount, category, description, date],
    (err, result) => {
      if (err) {
        console.log(err);
        return res.status(500).json({ message: 'Error adding expense' });
      }

      res.status(201).json({ message: 'Expense added successfully' });
    }
  )
})

app.get('/expenses', authenticate,(req,res)=>{

    const {filter,startDate,endDate} = req.query


    let query = 'SELECT * FROM expenses WHERE user_id = ?'

    let values = [req.userId]

    if(filter === 'week'){
        query += 'AND date >= DATE_SUB(NOW(),INTERVAL 7 DAY'
    }

    else if(filter === 'month'){
        query += 'AND date >= DATE_SUB(NOW(),INTERVAL 1 MONTH'

    }else if(filter === '3months'){
        query += 'AND date >= DATE_SUB(NOW(),INTERVAL 3 MONTH'
    }

    else if(filter === 'custom' && startDate && endDate){
        query += 'AND date BETWEEN ? AND ?'
        values.push(startDate, endDate)
    }

    db.query(query,values,(err,results)=>{
        if(err){
            console.log(err)
            return res.status(500).json({message:'Error fetching expenses'})
        }

        res.json(results)
    })
})


app.patch('/expenses/:id',authenticate, (req,res)=>{

    const expenseId = req.params.id
    const {amount,category,description,date} = req.body

    let updates = []
    let values = []

    if(amount){
        updates.push('amount = ?')
        values.push(amount)

    }
    
    if(category){
        updates.push('category = ?')
        values.push(category)
    }

    if(description){
        updates.push('description = ?')
        values.push(description)
    }

    if(date){
        updates.push('date = ?')
        values.push(date)
    }

    if(updates.length === 0){
        return res.status(400).json({message:'No fields to update'})

    }
    values.push(req.userId,expenseId)

    const query = `
    UPDATE expenses
    SET ${updates.join(' ,')}
    WHERE user_id = ? AND id = ?`

    db.query(query, values,(err,result)=>{
        if(err){
            console.log(err)
            return res.status(500).json({message:'Error updating expense'})
        }

        if(result.affectedRows === 0){
            return res.status(404).json({message:'Expense not found'})
        }
        res.json({message:'Expense updated successfully'})
    })
    
})

app.delete('/expense/:id',authenticate,(req,res)=>{

    const expenseId = req.params.id

    const query = 'DELETE FROM expenses WHERE user_id = ? AND id = ?'

    db.query(query,[req.userId,expenseId],(err,result)=>{
        if(err){
            console.log(err)
            return res.status(500).json({message:'Error deleting expense'})
        }
        if(result.affectedRows === 0){
            return res.status(404).json({message:'Expense not found'})
        }
        res.json({message:'Expense deleted successfully'})
    })
})


app.listen(3000,()=>{
    console.log('Server running')
})