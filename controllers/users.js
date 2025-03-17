let userSchema = require('../models/users');
let roleSchema = require('../models/roles');
let bcrypt = require('bcrypt')
let jwt = require('jsonwebtoken')
let constants = require('../Utils/constants')
const bcrypt = require('bcrypt');
const User = require('../models/user'); // Model User

// Hàm cập nhật mật khẩu
async function updatePassword(userId, newPassword) {
    try {
        let hashedPassword = await bcrypt.hash(newPassword, 10);
        let result = await User.updateOne({ _id: userId }, { password: hashedPassword });
        return result.modifiedCount > 0;
    } catch (error) {
        throw error;
    }
}

// Hàm lấy thông tin user theo ID
async function getUserById(userId) {
    return await User.findById(userId);
}

// Hàm kiểm tra mật khẩu có khớp không
async function comparePassword(inputPassword, storedPassword) {
    return await bcrypt.compare(inputPassword, storedPassword);
}

module.exports = {
    updatePassword,
    getUserById,
    comparePassword
};

module.exports = {
    getUserById: async function(id){
        return await userSchema.findById(id).populate("role");
    },
    createUser:async function(username,password,email,role){
        let roleCheck = await roleSchema.findOne({roleName:role});
        if(roleCheck){
            let newUser = new userSchema({
                username: username,
                password: password,
                email: email,
                role: roleCheck._id,
            });
            await newUser.save();    
            return newUser;  
        }else{    
            throw new Error("role khong ton tai");
        }

    },
    checkLogin: async function(username,password){
        if(username&&password){
            let user = await userSchema.findOne({
                username:username
            })
            if(user){
                if(bcrypt.compareSync(password,user.password)){
                    return jwt.sign({
                        id:user._id,
                        expired:new Date(Date.now()+30*60*1000)
                    },constants.SECRET_KEY);
                }else{
                    throw new Error("username or password is incorrect")
                }
            }else{
                throw new Error("username or password is incorrect")
            }
        }else{
            throw new Error("username or password is incorrect")
        }
    }
}