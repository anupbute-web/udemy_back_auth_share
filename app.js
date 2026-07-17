import dns from 'dns';
dns.setDefaultResultOrder('ipv4first');
import express from 'express';
import cors from 'cors';
import {v4 as uuid} from 'uuid';
import jwt from 'jsonwebtoken';
// import send_Mail from '../note_service/email/email.js';
import bcrypt from 'bcrypt';
import passport from 'passport';
import {Strategy as GoogleStrategy} from 'passport-google-oauth20';
import {Strategy as GithubStrategy} from 'passport-github2';
import crypto from 'crypto';
import userModel from './models/userschema.js';
import { registerValidation, loginValidation, req_user } from './Validate.js';
import myconnection from './db_connect/db.js';
import { G_CLIENT_ID_OAUTH2 , G_CLIENT_SECRET_OAUTH2 ,GT_CLIENT_ID_OAUTH2 , GT_CLIENT_SECRET_OAUTH2, MONGODB_URL } from './co.js'; 
import cookieParser from 'cookie-parser';
import Redis from 'ioredis';
     
const app = express();
     
app.use(cors({origin:'http://localhost:3000',credentials:true}));
app.use(express.json());
app.use(express.urlencoded({extended:true}));
app.use(cookieParser());
app.use(req_user);
app.use(passport.initialize());

let accT = '';

// passport.use(
//     new GithubStrategy(
//         {
//             clientID : GT_CLIENT_ID_OAUTH2,
//             clientSecret : GT_CLIENT_SECRET_OAUTH2,
//             callbackURL : 'http://localhost:4040/auth/github/callback'
//         },
//         (accessToken, refreshToken, profile, cb)=>{
//             if(!profile) return cb(new Error("cancle clicked") , null);
//             accT = accessToken
//             cb(null , profile);
//         }
//     )
// )

passport.use(
    new GoogleStrategy(
        {
            clientID : G_CLIENT_ID_OAUTH2,
            clientSecret : G_CLIENT_SECRET_OAUTH2,
            callbackURL : 'http://localhost:4040/auth/google/callback'
        },
        (accessToken , refreshToken , profile , cb)=>{
            if(!profile) return cb(new Error("cancle clicked") , null);
            cb(null , profile);
        }
    )
)
 
const io_redis = new Redis({
    host : '127.0.0.1',
    port : 6379
});

let [CODE_VERIFIED , CODE_PENDING , CODE_BLOCKED] = ["verified" , "pending" , "blocked"];

let retryAttemptsLUA = `
    local user = redis.call("HGETALL",KEYS[1])
    if next(user) ~= nil then
        local obj = {}
        for i=1 , #user , 2 do
            obj[user[i]] = user[i+1]
        end

        if obj["status"] == "blocked" then
            return {0,"blocked"}
        end
                
        if tonumber(obj["retryAttempts"]) <= 0 then
            redis.call("HSET" , KEYS[1] , "status" , "blocked")

            local keysToDelete = {}
            for k,v in pairs(obj) do
                if k ~= "status" then
                    table.insert(keysToDelete,k)
                end
            end
                    
            if #keysToDelete > 0 then
                redis.call("HDEL" , KEYS[1] , unpack(keysToDelete))
                redis.call("EXPIRE" , KEYS[1] , 300)
                return {0,"blocked"}
            end
        end

        redis.call("HINCRBY",KEYS[1],"retryAttempts",-1)
        return {1}

    else
        redis.call("HSET" , KEYS[1] , 
            "payload" , ARGV[1],
            "otp",ARGV[2],
            "retryAttempts" , "5",
            "verifyAttempts", "5",
            "resendAttempts", "5",
            "status","pending"
        )
        redis.call("EXPIRE" , KEYS[1] , 300)
        return {2}
    end   
`; 

let resendAttemptsLUA = `
local user = redis.call("HGETALL",KEYS[1])
    if next(user) ~= nil then
        local obj = {}
        for i=1 , #user , 2 do
            obj[user[i]] = user[i+1]
        end

        if obj["status"] == "blocked" then
            return {0,"blocked"}
        end
                
        if tonumber(obj["resendAttempts"]) <= 0 then
            redis.call("HSET" , KEYS[1] , "status" , "blocked")

            local keysToDelete = {}
            for k,v in pairs(obj) do
                if k ~= "status" then
                    table.insert(keysToDelete,k)
                end
            end
                    
            if #keysToDelete >= 0 then
                redis.call("HDEL" , KEYS[1] , unpack(keysToDelete))
                redis.call("EXPIRE" , KEYS[1] , 300)
                return {0,"blocked"}
            end
        end
        redis.call("HINCRBY",KEYS[1],"resendAttempts",-1)
        return {1,obj["payload"],obj["otp"]}
    else
        return {0,"blocked"}
    end
`;

let verifyAttemptsLUA = `
local user = redis.call("HGETALL",KEYS[1])
    if next(user) ~= nil then
        local obj = {}
        for i=1 , #user , 2 do
            obj[user[i]] = user[i+1]
        end

        if obj["status"] == "blocked" then
            return {0,"blocked"}
        end
                
        if tonumber(obj["verifyAttempts"]) <= 0 then
            redis.call("HSET" , KEYS[1] , "status" , "blocked")

            local keysToDelete = {}
            for k,v in pairs(obj) do
                if k ~= "status" then
                    table.insert(keysToDelete,k)
                end
            end
                    
            if #keysToDelete > 0 then
                redis.call("HDEL" , KEYS[1] , unpack(keysToDelete))
                redis.call("EXPIRE" , KEYS[1] , 300)
                return {0,"blocked"}
            end
        end

        if tonumber(ARGV[1]) == tonumber(obj["otp"]) then
            redis.call("HSET" , KEYS[1] , "status" , "verified")
            return {2,"otp success"}
        else
            redis.call("HINCRBY",KEYS[1],"verifyAttempts",-1)
            return {1,"wront otp"}
        end
    else
        return {0,"blocked"}
    end  
`;

let verifyAttemptsSHA , resendAttemptsSHA , retryAttemptsSHA;
(async ()=>{
    verifyAttemptsSHA = await io_redis.script("LOAD",verifyAttemptsLUA);
    resendAttemptsSHA = await io_redis.script("LOAD",resendAttemptsLUA);
    retryAttemptsSHA = await io_redis.script("LOAD",retryAttemptsLUA);
})();

// app.get('/auth/github',passport.authenticate('github',{scope:['profile','email'],session:false}));

// app.get(
//     '/auth/github/callback',

//     passport.authenticate('github', {
//         failureRedirect: 'http://localhost:3000/register',
//         session: false
//     }),

//     async (req, res) => {

//         try {

//             const authUser = req.user;
//             console.log(authUser)

//             // github email handling
//             const email = authUser.emails?.[0]?.value;

//             if (!email) {
//                 let response = await fetch(
//                 'https://api.github.com/user/emails',
//                 {
//                     headers:{
//                         Authorization:`token ${accT}`,
//                         Accept:'application/vnd.github+json'
//                     }
//                 }
//                 );

//                 let emails = await response.json();

//                 console.log(emails);
//                 return res.redirect('http://localhost:3000/');
//             }

//             let userDb = await userModel.findOne(
//                 { email },
//                 {
//                     email: 1,
//                     username: 1,
//                     role: 1
//                 }
//             );

//             if (!userDb) {

//                 const fullName =
//                     authUser.displayName ||
//                     authUser.username ||
//                     'github_user';

//                 const name = fullName.split(' ');

//                 userDb = new userModel({
//                     username: name[0],
//                     sirname: name[1] ?? '',
//                     email,

//                     authProvider: {
//                         providerName: authUser.provider, // github
//                         providerId: authUser.id
//                     }
//                 });

//                 await userDb.save();
//             }

//             // jwt
//             const access_token = jwt.sign(
//                 {
//                     _id: userDb._id,
//                     email: userDb.email,
//                     role: userDb.role
//                 },
//                 'anup',
//                 {
//                     expiresIn: '15m'
//                 }
//             );

//             const refresh_token = jwt.sign(
//                 {
//                     _id: userDb._id,
//                     email: userDb.email,
//                     role: userDb.role
//                 },
//                 'anup',
//                 {
//                     expiresIn: '30d'
//                 }
//             );

//             // cookies
//             res.cookie(
//                 'access_token',
//                 access_token,
//                 {
//                     httpOnly: true,
//                     secure: false,
//                     path: '/',
//                     maxAge: 15 * 60 * 1000
//                 }
//             );

//             res.cookie(
//                 'refresh_token',
//                 refresh_token,
//                 {
//                     httpOnly: true,
//                     secure: false,
//                     path: '/',
//                     maxAge: 30 * 24 * 60 * 60 * 1000
//                 }
//             );

//             // redis
//             const redisRes = await io_redis.set(
//                 `refresh_token:${userDb.email}`,
//                 refresh_token
//             );

//             if (!redisRes) {
//                 return res.json({success: false,msg: 'server error',data: null,error: null});
//             }
//             return res.redirect('http://localhost:3000/');
//         } catch (error) {
//             console.log(error);
//             return res.redirect('http://localhost:3000/login?error=auth_failed');
//         }
//     }
// );

app.get('/auth/google',passport.authenticate('google',{scope:['profile','email'],session:false}));


app.get('/auth/google/callback',
    passport.authenticate('google',{
        failureRedirect:'http://localhost:3000/register',
        session:false
    }),
    async (req,res)=>{
        try {
            let authUser = req.user;
            let userDb = await userModel.findOne({email:authUser.emails[0].value},{email:1,username:1,role:1,email:1,authProvider:1});
            if(!userDb){
                let name = authUser.displayName.split(' ');
                userDb = new userModel({
                    username:name[0],
                    sirname:name[1] ?? '',
                    email:authUser.emails[0].value,
                    authProvider:{
                        providerName : authUser.provider,
                        providerId : authUser.id
                    }
                });
                await userDb.save();
            }else if(userDb.authProvider.length <= 0){
                await userModel.findByIdAndUpdate(
                    userDb._id,
                    {
                        $set:{
                            authProvider:{
                                providerName:authUser.provider , 
                                providerId:authUser.id
                            }
                        }
                    }
                )
            }

            let access_token = jwt.sign({_id:userDb._id,email:userDb.email , role:userDb.role},'anup',{expiresIn:'15m'});
            let refresh_token = jwt.sign({_id:userDb._id , email:userDb.email , role:userDb.role},'anup',{expiresIn:'30d'});        
    
            res.cookie('access_token',access_token,{httpOnly:true , secure:false , path:'/' , maxAge:10*1000});
            res.cookie('refresh_token',refresh_token,{httpOnly:true , secure:false , path:'/' , maxAge:60*60*24*30*1000});

            if(!(await io_redis.set(`refresh_token:${userDb.email}`,`${refresh_token}`))) 
                return res.json({success:false , msg:'server error' , data:null , error:null});

            res.redirect('http://localhost:3000/');
        } catch (error) {
            console.log(error);
            res.redirect('http://localhost:3000/login?error=auth_failed');
        }
    }
)

app.post('/auth/register', registerValidation, async (req,res)=>{
    try {
        let {name, email, password:pass} = req.body;
        console.log(name)
        let user = await userModel.findOne({email},{email:1});

        if(user){
            return res.status(409).json({
                success:false,
                msg:'user already exists'
            });
        }

        let token = crypto.createHash('sha256').update(email).digest('hex');
        const hashPass = await bcrypt.hash(pass,10);
        let otp = `${Math.floor(100000 + Math.random() * 900000)}`;
        let payload = JSON.stringify({hashPass , email , name})

        let ok = await io_redis.evalsha(retryAttemptsSHA , 1 , token , payload , otp);

        if(ok[0] == 0) return res.json({token ,success:true , msg:'too many attempts'});
        else if(ok[0] == 1) return res.json({token ,success:true , msg:'otp sent again'});
        else if(ok[0] == 2){
            // let result = await send_Mail({receiver:email , subject:"otp" , text:`${otp}`});
            // if(!result) return res.status(500).json({success:false , msg:'otp not sent',}); 
            console.log(otp)
            return res.json({token ,success:true , msg:'otp sent succesfully'}).status(201);
        }    

        res.status(500).json({success:false , msg:'something wnt wrong'});
    } catch (error) {
        console.log('server error',error);
        res.status(500).json({success:false , msg:'server error'});
    }
});

app.post('/auth/register-final',async (req,res)=>{
    try {
        let token = req.body.token;
        if(!token) return res.status(409).json({success:false , msg:'something wnt wrong' , data:null , error:null});

        let [status , payload] = await io_redis.hmget(token , 'status' , 'payload')
        if(status !== CODE_VERIFIED) return res.status(409).json({success:false , msg:'someting went wrong' , data:null , error:null});

        payload = JSON.parse(payload);
        let name = payload.name.split(' ');
        console.log(name);
        let user = new userModel({
            username:name[0],
            sirname:name[1] ?? '',
            password:payload.hashPass,
            email:payload.email
        });
        await Promise.all([
            user.save(),
            io_redis.del(token)
        ])
        res.json({success:true , msg:'otp success' , data:{name:payload.name , email:payload.email} , error:null});
    } catch (error) {
        console.log(error);
        res.status(500).json({success:false , msg:'server error' , data:null , error:null})
    }
});

app.post('/auth/verify-otp',async(req,res)=>{
    try {
        
        let {token , otp} = req.body;
        if(!token || !otp || typeof Number(otp) !== "number" || otp.length > 6) return res.json({success:false , msg:'feilds'}).status(429);

        [token , otp] = [token.trim() , `${otp.trim()}`]
        let ok = await io_redis.evalsha(verifyAttemptsSHA , 1 , token , otp);

        if(ok[0]==0) return res.json({success:true , msg:'too many attempts' , data:null , error:null});
        if(ok[0]==1) return res.json({success:true , msg:'wrong otp retry' , data:{token} , error:null});
        if(Number(ok[0])==2) return res.json({ success:true , msg:'otp success' , data:{token} , error:null}).status(201);

        res.json({success:false , msg:'something ent wrong' , data:null , error:null})
    } catch (error) {
        console.log(error)
        res.json({success:false , msg:'server error'}).status(504);
    }
});

app.post('/auth/resend-otp',async(req,res)=>{
    try {
        let {token} = req.body;
        if(!token) return res.json({success:false , msg:'something went wrong'});

        let ok = await io_redis.evalsha(resendAttemptsSHA , 1 , token);
        if(ok[0]==0) return res.json({success:false , msg:'too many attempts'});
        else if(ok[0]==1) {
            let payload = JSON.parse(ok[1]);
            await send_Mail({receiver:payload.email,subject:'otp',text:ok[2]});
        }
        res.json({success:true , msg:'otp sent'});
    } catch (error) {
        console.log(error);
        return res.json({success:false , msg:'server error'});
    }
});  

app.post('/auth/login',loginValidation,async (req,res)=>{
    try {
        console.log(req.path,req.method)
        let {email,password} = req.body;

        let result = await userModel.findOne({email},{name:1 , email:1 , role:1 , password:1});

        if(!result || !await bcrypt.compare(password,result.password)){
            return res.json({success:false , msg:'wrong crediantls'});
        }
        console.log(await bcrypt.compare(password,result.password));
        let access_token = jwt.sign({_id:result._id,email:result.email , role:result.role},'anup',{expiresIn:'15m'});
        let refresh_token = jwt.sign({_id:result._id , email:result.email , role:result.role},'anup',{expiresIn:'30d'});        
 
        res.cookie('access_token',access_token,{httpOnly:true , secure:false , path:'/' , maxAge:10*1000});
        res.cookie('refresh_token',refresh_token,{httpOnly:true , secure:false , path:'/' , maxAge:60*60*24*30*1000});

        if(!(await io_redis.set(`refresh_token:${result.email}`,`${refresh_token}`))) return res.json({success:false , msg:'server error' , data:null , error:err});

        res.json({
            success:true , 
            msg:'user logged in' , 
            user:{
                id:result._id , 
                name:result.name , 
                email:result.email , 
                role:result.role
            },
            access_token
        });
    } catch (error) {
        console.log(error);
        res.json({success:false , msg:'server error'});
    }
});   

app.post('/auth/refresh-token',async(req,res)=>{
    try {
        let refresh_token = req.cookies.refresh_token;
        
        if(!refresh_token || typeof refresh_token !== 'string') return res.json({success:false , msg:'bad request' , data:null , error:null});
        
        let user = jwt.verify(refresh_token,'anup');
        
        if(!user) return res.json({success:false , msg:'bad request' , data:null , error:null});
        if(refresh_token !== await io_redis.get(`refresh_token:${user.email}`)) return res.json({success:false , msg:'unauthorized' , data:null , error:null});

        let access_token = jwt.sign({_id:user._id , email:user.email , role:user.role},'anup',{expiresIn:'15m'});
        refresh_token = jwt.sign({_id:user._id , email:user.email , role:user.role},'anup',{expiresIn:'30d'});  
        
        if(!(await io_redis.set(`refresh_token:${user.email}`,refresh_token))) return res.json({success:false , msg:'server error' , data:null , error:err});
 
        res.cookie('access_token',access_token,{httpOnly:true , secure:false , path:'/' , maxAge:10*1000});
        res.cookie('refresh_token',refresh_token,{httpOnly:true , secure:false , path:'/' , maxAge:60*60*24*30*1000});
        res.json({
            success:true , 
            msg:'user logged in' , 
            user:{
                id:user._id , 
                email:user.email , 
                role:user.role
            }
        });
    } catch (err) {
        console.log(err);
        res.json({success:false , msg:'server error' , data:null , error:err});        
    }
});
 
app.post('/auth/change-pass',async (req,res)=>{
    try {
        const { oldPassword:oldPass, newPassword:newPass } = req.body;
        const { user: token } = req;

        if(!newPass) 
            return res.json({success:false , msg:'missing feilds' , data:null , error:null});
        if(!token) 
            return res.status(401).json({success:false , msg:'unauthorized' , data:null , error:null});

        let dbUser = await userModel.findOne({_id:token._id},{password:1}).lean();
 
        if(dbUser.password && (!oldPass || oldPass === newPass)) 
            return res.json({success:false , msg:'wrong input' , data:null , error:null});
        if(dbUser.password && !await bcrypt.compare(oldPass,dbUser.password)) 
            return res.json({success:false , msg:'wrong pass try again' , data:null , error:null});

        await userModel.findByIdAndUpdate(token._id,{$set:{password:await bcrypt.hash(newPass,10)}});

        res.json({success:true , msg:'password updated' , data:null , error:null});
    } catch (error) {
        console.log(error);
        res.json({success:false , msg:'server error' , data:null , error});        
    }
}); 

app.post('/auth/change-email',async (req,res)=>{
    try {
        let user = req.user;
        let newEmail = req.body.email;
        console.log(user)

        if(!user) return res.status(401).json({success:false , msg:'unauthorie' , data:null , error:null});
        if(!newEmail || user.email == newEmail) return res.json({success:false , msg:'wrong input' , data:null , error:null});
        
        let userDb = await userModel.find({email:{$in:[user.email,newEmail]}},{email:1}).lean();

        let [isVerified,isExist] = [false,false]; 
        userDb.forEach(doc=>{
            if(doc.email == user.email) isVerified = true;
            if(doc.email == newEmail) isExist = true;
        });

        if (!isVerified) return res.status(401).json({success: false, msg: 'unauthorized'});
        if (isExist) return res.status(409).json({success: false, msg: 'new email exist'});

        let otp = Math.floor(100000 + Math.random() * 900000);
        let payload = JSON.stringify({oldEmail:user.email , newEmail , purpose:"change_email"})
        let token = crypto.createHash('sha256').update(user.email).digest('hex');

        let ok = await io_redis.evalsha(retryAttemptsSHA , 1 , token , payload , otp);
        console.log(ok)

        if(!ok) return res.json({success:false , msg:'redis error' , data:null , error:null});
        if(ok[0] == 0) return res.json({token ,success:false , msg:'too many attempts'});
        else if(ok[0] == 1) return res.json({token ,success:true , msg:'otp sent'});
        else if(ok[0] == 2){
            let result = true;
            // await send_Mail({receiver:newEmail , subject:"otp" , text:`${otp}`});
            if(!result) return res.status(500).json({success:false , msg:'otp not sent',}); 
            return res.json({token ,success:true , msg:'otp sent succesfully'}).status(201);
        }

        res.json({success:true , msg:'otp sent' , data:{email : user.email} , error:null});
    } catch (error) {
        console.log(error);
        res.json({success:false , msg:'server error' , data:null , error});
    }
});

app.post('/auth/change-email-final',async (req,res)=>{
    try {
        let token = req.body.token;
        if(!token) return res.status(409).json({success:false , msg:'something went wrong' , data:null , error:null});

        let [status , payload] = await io_redis.hmget(token , 'status' , 'payload')
        if(status !== CODE_VERIFIED) return res.status(409).json({success:false , msg:'something went wrong' , data:null , error:null});

        payload = JSON.parse(payload);
        await Promise.all([
            userModel.findOneAndUpdate(
                { email: payload.oldEmail },
                { email: payload.newEmail },
                { new: true }
            ),
            io_redis.del(token)
        ]);
        return res.json({success:true , msg:'otp success' , data:{email:newEmail} , error:null});
    } catch (error) {
        console.log(error);
        res.status(500).json({success:false , msg:'server error' , data:null , error:null})
    }
});

app.post('/auth/forgot-pass',async (req,res)=>{
    try {
        let email = req.body.email;
        if(!email || typeof email !== 'string') return res.json({success:false , msg:'empty feild' , data:null , error:null});

        let user = await userModel.findOne({email},{email:1});
        if(!user) return res.json({success:false , msg:'user not found' , data:null , error:null});

        let otp = crypto.randomInt(100000,900000);
        let token = crypto.createHash('sha256').update(email).digest('hex');
        let payload = JSON.stringify({email,otp});

        let ok = await io_redis.evalsha(retryAttemptsSHA , 1 , token , payload , otp);
        console.log(ok)

        if(ok[0] == 0){
            return res.json({success:false , msg:'too many attempts' , data:null , error:null});
        }else if(ok[0] == 1){
            return res.json({success:true , msg:'otp sent' , data:null , error:null});            
        }else if(ok[0]==2){
            send_Mail({receiver:email , subject:'otp' , text:`${otp}`});
            return res.json({success:true , msg:'otp sent' , data:{token} , error:null});
        }
        res.json({success:false , msg:'server error' , data:null , error});
    } catch (error) {
        console.log(error);
        res.json({success:false , msg:'server error' , data:null , error});
    }
});

app.patch('/auth/reset-pass',async(req,res)=>{
    try {
        let {token , pass} = req.body;
        if(!pass || !token || typeof pass != 'string' || typeof token !='string') 
            return res.json({success:false , msg:'empty feilds' , data:null , error:null});

        let [status,payload] = await io_redis.hmget(token,'status','payload');
        
        if(status !== CODE_VERIFIED) 
            return res.json({success:false , msg:'try again' , data:null , error:null});
        if(token !== crypto.createHash('sha256').update(JSON.parse(payload).email).digest('hex'))
            return res.json({success:false , msg:'wrong email' , data:null , error:null});

        let dbUser = await userModel.findOne({email:JSON.parse(payload).email},{email:1,password:1});
        if(!dbUser) 
            return res.json({success:false , msg:'user not found' , data:null , error:null});

        if(await bcrypt.compare(pass,dbUser.password)) 
            return res.json({success:false , msg:'new pass cannot same as old pass' , data:null , error:null});
        else{
            await Promise.all([
                userModel.findByIdAndUpdate(
                    dbUser._id,
                    {$set:{password:await bcrypt.hash(pass,10)}}
                ),
                io_redis.del(token)
            ]);
            return res.json({success:true , msg:'pass chnaged' , data:null , error:null});
        }
    } catch (error) {
        console.log(error);
        res.json({success:false , msg:'server error' , data:null , error:null})
    }
});

app.post('/auth/logout',async (req,res) => {
    try {
        let refresh_token = req.cookies.refresh_token;

        if(!refresh_token) return res.json({success:false , msg:'bad request' , data:null , error:null});

        let user = jwt.decode(refresh_token);

        await io_redis.del(`refresh_token:${user.email}`);

        res.clearCookie('access_token',{httpOnly:true , secure:false , path:'/'});
        res.clearCookie('refresh_token',{httpOnly:true , secure:false , path:'/'});

        res.set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
        res.set('Pragma', 'no-cache');
        res.set('Expires', '0');  
        
        res.json({success:true , msg:'logged out' , data:null , error:null})
    } catch (err) {
        console.log(err)
        res.json({success:false , msg:'server error' , data:null , error:err});    
    }
});
    
async function startServer(){
    await myconnection();
    app.listen(4041, () => console.log(`auth_service on 4041`));
}

startServer();


// message ReviewRequest {
//     string course_id = 1; 
// }

// message ReviewListRequest{
//     repeated ReviewRequest list = 1;
// }

// message Review {
//     string user = 1;
//     int32 rating = 2;
//     string comment = 3;
// }

// message ReviewListResponse {
//     repeated Review reviews = 1;
// }