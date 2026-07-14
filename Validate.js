import xss from 'xss';
import joi from 'joi';
function loginValidation(req,res,next){
    let schema = joi.object({
        email:joi.string().email().required(),
        password:joi.string().required()
    });

    const {error , value} = schema.validate(req.body);

    if(error){
        return res.json({success:false , msg:'input validation error'});
    }
    next();
}

function registerValidation(req,res,next){
    let schema = joi.object({
        name:joi.string().min(3).required(),
        email:joi.string().email().required(),
        password:joi.string().required(),
    });

    const {error , value} = schema.validate(req.body);
    if(error){
        console.log(error);
        return res.status(400).json({
            success:false,
            msg:"input validation error"
        })
    }
    value.name = xss(value.name);
    req.body = value;
    
    next();
};


function req_user(req,res,next){
    if(req?.headers?.['x-user-data'])
        req.user = JSON.parse(req.headers['x-user-data']);
    next();
}

export {registerValidation , loginValidation , req_user};