const mongoose = require ('mongoose');
const bcrypt = require('bcryptjs');

const employeeSchema = new mongoose.Schema({
    EmployeeId:{
        type: String,
        required: true,
        unique: true,
        match: /^[A-Za-z0-9]+$/

    },
    password: {
        type: String,
        required: true
    },
    role: {
        type: String,
        enum:['Admin', 'Finance', 'Support'],
        required: true
    }
});

employeeSchema.pre('save', async function (next){
    if(!this.isModified('password')) return next ();
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
});

module.exports = mongoose.model('Employee', employeeSchema);