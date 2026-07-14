import mongoose from "mongoose";

const courseCollection = new mongoose.Schema({
    title : {
        type : String,
        required : true
    },
    subTitle : {
        type : String,
        required : true
    },
    instructor : {
        type : String,
        required : true
    },
    category : {
        type : String,
        required : true
    },
    url : {
        type : String,
        required : true
    },
    imgUrl : {
        type : String,
        required : true
    },
    price : {
        type : String,
        required : true
    },
    is_paid : {
        type : Boolean,
        required : true
    },
    tag : {
        type : String
    },
    rating : {
        type : Number,
        required : true
    },
    students_enrolled : {
        type : Number,
        required : true
    },
    languages_available : {
        type : Array,
        required : true
    },
    content_duration : {
        type : String,
        required : true
    },
    number_of_lectures : {
        type : Number,
        required : true
    },
    requirments : {
        type : Array
    },
    what_you_will_learn : {
        type : Array,
        required : true
    },
    sections : {
        type : Array,
        required : true
    }
});

const courseModel = mongoose.model('courses',courseCollection);

export default courseModel;