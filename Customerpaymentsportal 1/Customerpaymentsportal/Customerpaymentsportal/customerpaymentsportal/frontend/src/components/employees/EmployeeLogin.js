import React, { useState } from 'react';
import axios from 'axios';

const EmployeeLogin = () => {
    const [usernameEmplo, setUsername] = useState('');
    const [passwordEmplo, setPassword] = useState('');
    const [message, setMessage] = useState('');

    const manageLogin = async (e) => {
        e.preventDefault();

        const usernameReg = /^[a-zA-Z0-9_]+$/;
        if (!usernameReg.test(usernameEmplo)) {
            setMessage('This is the incorrect username format');
            return;
        }
        try {
            const response = await axios.post('http://localhost:5000/api/employee-login', { usernameEmplo, passwordEmplo });
            setMessage(response.data.message);
        } catch (error) {
            setMessage(error.response?.data?.message || 'An error occurred');
        }
    };

    return (
        <div style={{ backgroundColor: '#f0f8ff', padding: '20px', borderRadius: '10px' }}>
            <form onSubmit={manageLogin}>
                <input
                    type="text"
                    placeholder="Username of Employee"
                    value={usernameEmplo}
                    onChange={(e) => setUsername(e.target.value)}
                    required
                />
                <input
                    type="password"
                    placeholder="Enter Password"
                    value={passwordEmplo}
                    onChange={(e) => setPassword(e.target.value)}
                    required
                />
                <button type="submit" className="bold-text">Login</button>
            </form>
            {message && <p>{message}</p>}
        </div>
    );
};

export default EmployeeLogin;