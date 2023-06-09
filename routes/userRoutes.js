const express = require('express');
const router = express.Router();
const {
    getUser,
    updateUser,
    forgotPassword,
    resetPassword,
    changePassword,
    uploadAvatar,
    findByName,
    uploadImage,
    getChatList,
    addMemberToGroup,
    viewMessagesOfChatRoom,
} = require('./../controllers/userController');
const auth = require('./../middlewares/auth');

router.route('/me').get(auth.protectedAPI, getUser).patch(auth.protectedAPI, updateUser);
router.route('/forgot-password').post(forgotPassword);
router.route('/reset-password/:token').patch(resetPassword);
router.route('/uploadAvatar').post( auth.protectedAPI, uploadImage, uploadAvatar);
router.route('/find/:fullname').get(auth.protectedAPI, findByName)
router.route('/change-password').patch(changePassword);
router.route('/chat-list').get(getChatList);
router.route('/add-member-to-group').patch(addMemberToGroup);
router.route('/view-chatroom-messages').get(viewMessagesOfChatRoom);
module.exports = router;

// passport.authenticate('jwt', { session: false }), getUser
