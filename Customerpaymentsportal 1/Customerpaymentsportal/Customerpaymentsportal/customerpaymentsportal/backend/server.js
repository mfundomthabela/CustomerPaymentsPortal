const express = require('express');
const mongoose = require('mongoose');
const sslify = require('express-sslify'); // Import express-sslify
const bcrypt = require('bcrypt'); // Import bycrypt
const helmet = require('helmet');
const userRoutes = require('./routes/userRoutes'); // Import user routes


const app = express();

app.use(helmet());

// Use express-sslify to redirect HTTP to HTTPS
app.use(sslify.HTTPS({ trustProtoHeader: true }));

// Middleware for parsing application/json
app.use(express.json());

// Connect to MongoDB (update the connection string as necessary)
const mongoURI = 'mongodb://localhost:27017/payments'; // Your MongoDB URI
mongoose.connect(mongoURI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
}).then(() => {
  console.log('MongoDB connected successfully');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

// Sample route
app.get('/', (req, res) => {
  res.send('Welcome to the Customer International Payments Portal');
});

// User routes
app.use('/api/users', userRoutes); // Connect user routes

let employees = [];
app.post('/api/create-employee', async (req, res) => {
  const {usernameEmplo, passwordEmplo} = req.body;

  const usernameReg = /^[a-zA-Z0-9_]+$/;
  if(!usernameReg.test(usernameEmplo)){
    return res.status(400).json({message: 'You Have Inserted The Incorrect Employee Username Format'});
  }
  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(passwordEmplo, salt);

  const newEmployee = {usernameEmplo, passwordEmplo: hashedPassword};
  employees.push(newEmployee);
  res.status(201).json({message: 'Employee Account Has Been Created',employee: newEmployee});

});
app.post('/api/employee-login', async(req, res) => {
  const{usernameEmplo, passwordEmplo} = req.body;
  const employee = employees.find(e => e.usernameEmplo === usernameEmplo);

  if(!employee){
    return res.status(400).json({message: 'ERROR!!Invaild Credentials'});
  }
  const isMatch = await bcrypt.compare(passwordEmplo, employee.passwordEmplo);
  if(!isMatch){
    return res.status(400).json({message: 'ERROR!!Invaild Credentials'});
  }
  res.json({message: 'Logged In Successfully'});

});


const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
