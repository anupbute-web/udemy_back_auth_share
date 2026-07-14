import mongoose from "mongoose";
const userSchema = new mongoose.Schema({
    username : {
        type : String,
        trim : true,
        required : function(){
            return !this.authProvider || this.authProvider.length === 0
        }
    },
    sirname:{
        type:String,
        default:''
    },
    email : {
        type : String,
        unique : true,
        lowercase : true,
        trim : true,
        required : true
    },
    password : {
        type : String,
        required : function(){
            return !this.authProvider || this.authProvider.length === 0;
        }
    },
    role : {
        type : String,
        enum : ['student','instructor','admin'],
        default : 'student'
    },
    linkdin_link:{
        type:String,
        default:''
    },
    leetcode_link:{
        type:String,
        default:''
    },
    github_link:{
        type:String,
        default:''
    },
    bio:{
        type:String,
        default:''
    },
    authProvider : {
        type : [
            {
                providerName : String,
                providerId : String
            }
        ],
        default : []
    },
    learnings:[
        {
        type:mongoose.Schema.ObjectId,
        ref:'courses',
        default:[]
        }
    ],
    cart:[
        {
        type:mongoose.Schema.ObjectId,
        ref:'courses',
        default:[]
        }
    ],
    createdAt : {
        type : Date,
        default : Date.now()
    }
});

let userModel = mongoose.model("User",userSchema);

export default userModel;