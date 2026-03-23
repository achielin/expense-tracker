const jwt = require('jsonwebtoken')

const authenticate = (req,res,next) =>{
    const authHeader = req.headers.authorization

    if(!authHeader){
        return res.status(401).json({message:'No token provided'})
    }

    try{
        const token = authHeader.split(' ')[1]

        const decoded = jwt.verify(token,process.env.JWT_SECRET)

        req.userId = decoded.userId

        next()
    }catch(err){
        return res.status(401).json({message:'Invalid token'})

    }
}

module.exports = authenticate