let jwt = require('jsonwebtoken')
let constants = require('../Utils/constants')
let userController = require('../controllers/users')
const jwt = require('jsonwebtoken');
const User = require('../models/user');

// Middleware kiểm tra authentication
function check_authentication(req, res, next) {
    const token = req.header('Authorization');
    if (!token) {
        return res.status(401).send({ success: false, message: "Vui lòng đăng nhập." });
    }
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        res.status(401).send({ success: false, message: "Token không hợp lệ." });
    }
}

// Middleware kiểm tra quyền admin
async function check_admin(req, res, next) {
    try {
        let user = await User.findById(req.user.id);
        if (!user || user.role !== "admin") {
            return res.status(403).send({ success: false, message: "Bạn không có quyền truy cập." });
        }
        next();
    } catch (error) {
        res.status(500).send({ success: false, message: "Lỗi hệ thống." });
    }
}

module.exports = { check_authentication, check_admin };

module.exports={
    check_authentication: async function(req,res,next){
        if(req.headers.authorization){
            let token_authorization = req.headers.authorization;
            if(token_authorization.startsWith("Bearer")){
              let token = token_authorization.split(" ")[1];
              let verifiedToken = jwt.verify(token,constants.SECRET_KEY);
              if(verifiedToken){
                console.log(verifiedToken);
                let user = await userController.getUserById(
                    verifiedToken.id  
                )
                req.user = user;
                next()
              }
            }else{
              throw new Error("ban chua dang nhap")
            }
          }else{
            throw new Error("ban chua dang nhap")
          }  
    },
    check_authorization: function(roles){
        return function(req,res,next){
            if(roles.includes(req.user.role.roleName)){
                next();
            }else{
                throw new Error("ban khong co quyen")
            }
        }
    }
}