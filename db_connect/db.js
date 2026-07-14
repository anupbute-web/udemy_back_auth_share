import mongoose from "mongoose";
import {MONGODB_URL} from '../co.js'
async function myconnection(){
    try {
        await mongoose.connect(MONGODB_URL);
        console.log('db connected');
    } catch (error) {
        console.log(error);
    }
}
export default myconnection;
