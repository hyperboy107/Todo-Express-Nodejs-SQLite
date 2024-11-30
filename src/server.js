//express bcrypyjs jsdonwebtoken
// const express = require('express')
//Thats the new importing for express
import express from 'express'
import path, {dirname} from 'path'
import { fileURLToPath } from 'url'

import apiAuth from './routes/apiAuth.js'
import todoWebsite from './routes/todoWebsite.js'
import authMiddleware from './middleware/auth.js'

const app = express()
const PORT = process.env.PORT || 5000 

//Get the file path from the url of the current module
const __filename = fileURLToPath(import.meta.url);

//get the directory name from the file path
const __dirname = dirname(__filename)

//Middleware
app.use(express.json())
//Serving the html file from /public directory
//Also tells express to serve all files from the public folder as static assests / files
//Any req for css files will be resolved to the public directory.

app.use(express.static(path.join(__dirname, '../public')))


//Serving the html file from the /public directory
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'))
})

//Routes
app.use('/auth', apiAuth);
app.use('/todos',authMiddleware, todoWebsite)

app.listen(PORT, () => {
    console.log(`Server has started on PORT: ${PORT}`);
})
