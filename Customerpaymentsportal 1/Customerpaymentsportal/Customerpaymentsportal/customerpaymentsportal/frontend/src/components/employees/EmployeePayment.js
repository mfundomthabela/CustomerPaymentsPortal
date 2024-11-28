import React, {useState} from 'react';
import axios from 'axios';

const EmployeePayment = () => {
    
    const [total, setTotal] = useState('');
    const[receiver, setReceiver]= useState('');
    const[message, setMessage]= useState('');

    const managePayment = async (e) => {
        e.preventDefault();
        const totalReg = /^[0-9]+(\.[0-9]{1,2})?$/;
        if(!totalReg.test(total)){
            setMessage('ERROR!!Not The Correct Format');
            return;
        }
        try{const response = await axios.post('http://localhost:5000/api/employee-payment', {total, receiver});
    setMessage(response.data.message);
}catch(error){setMessage(error.response.data.message);
}
    };
    return(
        <div style={{backgroundColor: '#f0f8ff', padding: '20px', borderRadius: '10px'}}>
            <form onSubmit={managePayment}>
            <input
            type="text"
            placeholder="Received By"
            value={receiver}
            onChange={(e) => setReceiver(e.target.value)} required />
            <input
            type="text"
            placeholder="The Total Amount"
            value={total}
            onChange={(e) => setTotal(e.target.value)} required />
            <button type="submit">Pay</button>
            </form>
            {message && <p>{message}</p>}
            </div>
    );
};
export default EmployeePayment;