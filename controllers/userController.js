const User = require('./../models/User');
const ChatGroup = require('./../models/ChatGroup');
const createError = require('http-errors');
const sendEmail = require('./../utils/mailSender');
const { signAccessToken, signRefreshToken } = require('../utils/jwtToken');
const multer = require('multer');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cloudinary = require("./../utils/cloudinaryConfig")

exports.getAllUsers = async (req, res) => {
    try {
        next();
    } catch (err) {
        console.error(err);
        return next(createError.BadRequest('Bad request'));
    }
};

// TODO: US 15: let user view their profile
exports.getUser = async (req, res, next) => {
    try {
        const user = await User.findById(req.user.id).populate('chatgroups');

        return res.status(200).json({
            success: true,
            data: {
                user,
            },
        });
    } catch (err) {
        console.error(err);
        return next(createError.BadRequest('Bad request'));
    }
};

exports.createUser = async (req, res) => {
    try {
        const newUser = await User.create(req.body);
        console.log(newUser);
        res.status(200).json({
            success: true,
            data: {
                user: newUser,
            },
        });
    } catch (err) {
        console.error(err);
        return next(createError.BadRequest('Bad request'));
    }
};

// TODO: US 15: let user update their profile
exports.updateUser = async (req, res, next) => {
    try {
        console.log(req.body);
        const user = await User.findByIdAndUpdate(req.user.id, req.body, {
            new: true,
            runValidators: true,
        });
        res.status(200).json({
            success: true,
            data: {
                user,
            },
        });
    } catch (err) {
        console.error(err);
        return next(createError.BadRequest('Bad request'));
    }
};

exports.deleteUser = async (req, res) => {
    try {
        await User.findByIdAndDelete(req.params.id);
        res.status(204).json({
            success: true,
            data: null,
        });
    } catch (err) {
        console.error(err);
        return next(createError.BadRequest('Bad request'));
    }
};

// TODO: reset password by sending reset token via email
exports.forgotPassword = async (req, res, next) => {
    //1. get user
    const user = await User.findOne({ email: req.body.email });
    if (!user) {
        return next(createError.NotFound('There is no user founded with email address'));
    }

    //2. generate random token
    const resetToken = user.genResetPasswordToken();
    await user.save({ validateBeforeSave: false });

    //3. send it to user email
    const resetURL = `${req.protocol}://${req.get(
        'host'
    )}/api/v1/users/reset-password/${resetToken}`;

    const message = `Quên mật khẩu của bạn? Nhập mật khẩu mới và xác nhận mật khẩu tại đường dẫn sau: ${resetURL}\n`;
    try {
        await sendEmail({
            email: user.email,
            subject: 'Đường link lấy lại mật khẩu (có hiệu lực trong 10 phút)',
            message,
        });
        console.log(resetURL);

        res.status(200).json({
            success: true,
            resetToken,
            message: 'Token sent to email',
        });
    } catch (err) {
        console.log(err);
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save({ validateBeforeSave: false });
        return next(
            createError.InternalServerError(
                'Something went wrong when sending the email. Try again later'
            )
        );
    }
};

exports.resetPassword = async (req, res, next) => {
    console.log(req.params.token);
    const user = await User.findOne({
        resetPasswordToken: req.params.token,
        resetPasswordExpires: { $gt: Date.now() },
    });
    if (!user) {
        return next(createError.BadRequest('Token invalid or token has expires'));
    }

    user.password = req.body.password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save({ validateBeforeSave: false });
    const accessToken = signAccessToken(user._id);
    const refreshToken = signRefreshToken(user._id);

    res.status(200).json({
        success: true,
        accessToken,
        refreshToken,
        data: {
            user,
        },
    });
};

exports.changePassword = async (req, res, next) => {
    console.log('Change password api route');
    try {
        const oldPassword = req.body.oldPassword;
        const newPassword = req.body.newPassword;
        const confirmPassword = req.body.confirmPassword;

        const accessToken = req.headers.authorization;
        if(!accessToken) return res.status(401).json({success: false, message: "Access token not found"})
        const accessTokenArray =  accessToken.split(' ');
        if(accessTokenArray.length === 1 || accessTokenArray[0] !== 'Bearer') return res.status(400).json({message: "Your token have wrong key"})
        const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
        const verify = jwt.verify(accessTokenArray[1], accessTokenSecret)
        User.findById({_id: verify.id}, (err, user) => {
            if(err) return res.json("Query error")
            bcrypt.compare(oldPassword, user.password, (err, result) => {
                if (result) {
                    if (newPassword === confirmPassword) {
                        user.password = newPassword;
                        user.save();
                    }
                }
            });
        });

        return res.status(200).json({
            success: true,
            message: 'Congratulation! Password succesfully changed!',
            user: req.user,
        });
    } catch (err) {
        console.log(err);
        res.json({ success: false, message: 'Trycatch error', error: err });
    }
};

const multerConfig = multer.diskStorage({
    destination: (req, file, callback) => {
        callback(null, 'uploads/avatar');
    },
    filename: (req, file, callback) => {
        const ext = file.mimetype.split('/')[1];
        callback(null, `${req.user.id}.${ext}`);
    },
});
const upload = multer({
    storage: multerConfig,
});
exports.uploadImage = upload.single('photo');

exports.uploadAvatar = async (req, res, next) => {
    try {
        // console.log(req.file.path.split("\\").pop());
        const dirPath = req.file.destination;
        const localPath = req.file.path;
        const cloudfilePath = `ChatApp/${dirPath}`
        const result = await cloudinary.uploader.upload(localPath, {
            folder: cloudfilePath,
            public_id: `${req.user.id}`
        })

        res.status(200).json({
            success: true,
            data:{
                url: result.url
            }
        });
    } catch (err) {
        console.log(err);
        return next(createError.NotFound("Cant not upload to cloud"))
    }
};

exports.findByName = async (req, res, next) => {
    try {
        const { fullname } = req.params;
        const user = await User.find({ fullname }).populate('chatgroups');
        return res.status(200).json({
            success: true,
            data: {
                user,
            },
        });
    } catch (arr) {
        console.error(err);
        return next(createError.BadRequest('Bad request'));
    }
};

exports.getChatList = async (req, res) => {
    try {
        const accessToken = req.headers.authorization;
        if(!accessToken) return res.status(401).json({success: false, message: "Access token not found"});
        const accessTokenArray =  accessToken.split(' ');
        if(accessTokenArray.length === 1 || accessTokenArray[0] !== 'Bearer') return res.status(400).json({message: "Your token have wrong key"})
        const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
        const verify = jwt.verify(accessTokenArray[1], accessTokenSecret)
        
        const user = await User.findOne({_id: verify.id}).populate('chatgroups')
        const result = user.chatgroups
        if(!user) return res.status(500).json({success: false, message: "You do not have access right to use this feature"})
        
        console.log('result:', user)
        return res.status(200).json({succes: true, message: "Successfully get chat list", chatList: result})
    } catch (error) {
        res.status(500).json({success: false, error: error})
        console.log(error)
    }
}


exports.addMemberToGroup = async (req, res) => {
    try {
        const userId = req.body.userId;
        const groupId = req.body.groupId;
        const accessToken = req.headers.authorization;
        if(!accessToken) return res.status(401).json({success: false, message: "Access token not found"});
        const accessTokenArray =  accessToken.split(' ');
        if(accessTokenArray.length === 1 || accessTokenArray[0] !== 'Bearer') return res.status(400).json({message: "Your token have wrong key"})
        const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
        const verify = jwt.verify(accessTokenArray[1], accessTokenSecret)

        const group = await ChatGroup.findOne({_id: groupId})
        if(!group) return res.status(401).json({message: "Group not found"})

        // check authorization
        const userAccess = await User.findOne({_id: verify.id}).populate('chatgroups');
        console.log(group);
        console.log('------------------------------------------------------------')
        console.log(userAccess.chatgroups)
        if(!userAccess) return res.status(401).json({message: "You do not have access right to use this feature!"})
        
        if(!(group.members.includes(userAccess._id))) return res.status(500).json({message: "You do not in this room to add any member!"})
        if(group.members.includes(userId)) return res.status(400).json({message: "This user is already in this group"})
        
        User.findById({_id: userId}, (err, userFound) => {
            if(err) throw err;
            if(!userFound) return res.status(401).json({message: "User not found"});
            group.members.push({_id: userFound._id, fullname: userFound.fullname});
            group.save();
            userFound.save();
            res.status(200).json({groupMembers: group})
        })
    } catch (error) {
        res.status(500).json({success: false, error: error})
        console.log(error)
    }
}


exports.viewMessagesOfChatRoom = async (req, res) => {
    try {
        const accessToken = req.headers.authorization;
        if(!accessToken) return res.status(401).json({success: false, message: "Access token not found"});
        const accessTokenArray =  accessToken.split(' ');
        if(accessTokenArray.length === 1 || accessTokenArray[0] !== 'Bearer') return res.status(400).json({message: "Your token have wrong key"})
        const accessTokenSecret = process.env.ACCESS_TOKEN_SECRET;
        const verify = jwt.verify(accessTokenArray[1], accessTokenSecret)
        const user = await User.findOne({_id: verify.id});
        if(!user) return res.status(401).json({success: false, message: "User not found"})
        let result = []
        const group = await ChatGroup.findOne({_id: req.body.chatGroupId}).populate('messages')
        if(!group) return res.status(404).json({message: "Group not found"})
        if(!(group.members.includes(user._id))) return res.json({success: false, message: "You are not in the room"})
        result = group.messages;
        console.log(result)

        res.status(200).json({message: result})
    } catch (error) {
        res.status(500).json({success: false, error: error})
        console.log(error)
    }
}
