
const express = require('express');
const {connection} =require("./db")
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(bodyParser.json());

const userRoutes = require('./routes/user.routes');
const blogRoutes = require('./routes/blog.routes');

app.use('/api', userRoutes);
app.use('/api', blogRoutes);

app.listen(process.env.port,async()=>{
    try{
        await connection
        console.log("connect to the DB");
        console.log(`server is running at port ${process.env.port}`);
    }catch(err){
        console.log(err);
        console.log("Something Went Wrong!!!");
    }
})