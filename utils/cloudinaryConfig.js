const constant = require('./../const')

const cloudinary = require("cloudinary").v2;
cloudinary.config({
    cloud_name: constant.CLOUDINARY_NAME,
    api_key: constant.CLOUDINARY_API_KEY,
    api_secret: constant.CLOUDINARY_API_SECRET
})
module.exports = cloudinary;