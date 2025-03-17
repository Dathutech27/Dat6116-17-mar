var express = require('express');
var router = express.Router();
let userController = require('../controllers/users');
const { check_authentication, check_admin } = require('../Utils/check_auth'); // Middleware kiểm tra quyền

// Reset password về 123456 (Chỉ Admin mới có quyền)
router.get('/resetPassword/:id', check_authentication, check_admin, async function(req, res, next) {
    try {
        let userId = req.params.id;
        let newPassword = "123456";
        let result = await userController.updatePassword(userId, newPassword);
        
        if (result) {
            res.status(200).send({
                success: true,
                message: "Mật khẩu đã được đặt lại thành công."
            });
        } else {
            res.status(400).send({
                success: false,
                message: "Không thể đặt lại mật khẩu."
            });
        }
    } catch (error) {
        next(error);
    }
});

// Change password (User phải đăng nhập)
router.post('/changePassword', check_authentication, async function(req, res, next) {
    try {
        let userId = req.user.id;  // Lấy ID user từ token đăng nhập
        let { password, newPassword } = req.body;

        let user = await userController.getUserById(userId);

        if (!user) {
            return res.status(404).send({
                success: false,
                message: "Người dùng không tồn tại."
            });
        }

        let isMatch = await userController.comparePassword(password, user.password);
        if (!isMatch) {
            return res.status(400).send({
                success: false,
                message: "Mật khẩu hiện tại không đúng."
            });
        }

        let result = await userController.updatePassword(userId, newPassword);
        if (result) {
            res.status(200).send({
                success: true,
                message: "Mật khẩu đã được thay đổi thành công."
            });
        } else {
            res.status(400).send({
                success: false,
                message: "Không thể thay đổi mật khẩu."
            });
        }
    } catch (error) {
        next(error);
    }
});

module.exports = router;
