//D:\workspace\practice_lab16\src\routes\usersRoutes.ts
//1.ทำการ copy usersRoutes จาก github
import { Router, type Request, type Response } from "express";

// ******ทำการติดตั้งทั้ง 3 อันนี้ด้วย*********
import jwt from "jsonwebtoken";             //pnpm install jsonwebtoken, pnpm i jsonwebtoken, pnpm i -D @types/jsonwebtoken
import dotenv from "dotenv";                //pnpm install dotenv
dotenv.config();

import type { User, CustomRequest } from "../libs/types.js";

// import database
import { users, reset_users } from "../db/db.js";
import { zStudentId } from "../libs/zodValidators.js";


// import authenticateToken && checkRoleAdmin
import { authenticateToken } from "../middlewares/authenMiddleware.js";
import { checkRoleAdmin } from "../middlewares/checkRoleAdminMiddleware.js";

/*
import { checkRoleStudent } from "../middlewares/checkRoleStudentMiddleware.js";
import { checkAllRoles } from "../middlewares/checkAllRolesMiddleware.js";
*/

const router = Router();

// GET /api/v2/users    (get แล้วได้ user ทั้งหมด ทั้งหมดกลับไป)
router.get("/", authenticateToken, checkRoleAdmin, (req: Request, res: Response) => {
  try { /*
    //Get Authorization headers
    const authHeader = req.headers["authorization"]
    console.log(authHeader)

    // if authHeader is not found or wrong format
    if (!authHeader || !authHeader.startsWith("Bearer")) {      //เช็กก่อนว่ามันมีค่าหรือป่าว
        return res.status(401).json({                           //401 คือ unAuthorise
            success: false,
            meaasge: "Authorization header is not found"
        });
    }       


    //extract token and check of token is available
    const token = authHeader?.split(" ")[1]                     // เราจะได้ array ของข้อความทั้งหมดที่ขั้นด้วย spacebar 

    if (!token) {
        return res.status(401).json({
            success: false,
            message:"Token is required"
        });
    }

    try {
        const jwt_secret = process.env.JWT_SECRET || "forget_secret";
        jwt.verify(token, jwt_secret, (err,payload) => {
            if (err) {
                return res.status(403).json({
                    success: false,
                    message: "invalid or expired token"
                });
            }

            const user = users.find(
                (u: User) => u.username === (payload as UserPayload).username         
                //ดึง Users มาดูทีละคน โดยแต่ละคนเราจะดูว่าค่าที่ส่งมามันตรงกับค่าที่ส่งมาใน request ไหม 

            );

            if(!user || user.role != "ADMIN"){
          return res.status(401).json({
            success: false,
            massage: "Unauthorized user"
          })
        } 

        */

        return res.status(200).json({
          success: true,
          massage: "Successful operation",
          data: users
        })

    /*
    } catch (err) {
        return res.status(200).json({
            success: false,
            message: "Something is wrong, please try again",
            error: err,
        });
    }
    */

    /*
    // return all users
    return res.json({
      success: true,
      data: users,
    });
    */

  } catch (err) {
    return res.status(200).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});




// POST /api/v2/users/login
router.post("/login", (req: Request, res: Response) => {
    try {
        // 1. get username and password from body
        const { username, password } = req.body;          //เพราะข้อมูลเราอยู่ใน body ทั้ง 2 ตัว
        const user = users.find(
            (u: User) => u.username === username && u.password === password         
            //ดึง Users มาดูทีละคน โดยแต่ละคนเราจะดูว่าค่าที่ส่งมามันตรงกับค่าที่ส่งมาใน request ไหม 

        );

        // 2. check if user exists (search with username & password in DB)      (เช็ก user ว่า คนที่คุณค้นมามันมีค่าจริงหรือป่าว)
        // ในกรณีที่ไม่มี user
        if (!user) {
            return res.status(401).json ({
                success: false,
                message: "Invalid username or password!"
            });
        }


        // 3. create JWT token (with user info object as payload) using JWT_SECRET_KEY
        //    (optional: save the token as part of User data)

        // ในกรณีที่มี user
        //ขั้นแรกต้องไปดึง secret มาก่อน
        const jwt_secret = process.env.JWT_SECRET || "forget_secret";
        //มีค่า key แล้ว
        //นำ key ไปใช้ในการเข้ารหัส

        //สร้าง Token
        const token = jwt.sign({                //ต้องการ playload (ข้อมูลที่ server อยากจะฝากฝังเข้าไปเก็บไว้ใน token ด้วย)
            //create JWT playload               // playload เอาไว้เพิ่มชื่อ บลาๆ~~ (แนบข้อมูลเท่าที่จำเป็น เผื่อมีคนเอาไปแกะ)
            username: user.username,
            studentId: user.studentId,
            role: user.role,
        },jwt_secret, { expiresIn: "5m" });     // jwt_secret เอาไว้ใช้เข้ารหัส && ฟังก์ชันเพิ่มเติม (Ex. { expiresIn: "5m" })



        // 4. send HTTP response with JWT token         //ทำการส่ง response กลับไป
        res.status(200).json({
            success: true,
            message: "Login successful",
            token                                       //อย่าลืมใส่ token
        })
    } catch (error) {
        return res.status(500).json({
            success: false,
            message: "Something went wrong.",
            error: error
        })
    }
  

  return res.status(500).json({
    success: false,
    message: "POST /api/v2/users/login has not been implemented yet",
  });
});

// POST /api/v2/users/logout
router.post("/logout", (req: Request, res: Response) => {
  // 1. check Request if "authorization" header exists
  //    and container "Bearer ...JWT-Token..."

  // 2. extract the "...JWT-Token..." if available

  // 3. verify token using JWT_SECRET_KEY and get payload (username, studentId and role)

  // 4. check if user exists (search with username)

  // 5. proceed with logout process and return HTTP response
  //    (optional: remove the token from User data)

  return res.status(500).json({
    success: false,
    message: "POST /api/v2/users/logout has not been implemented yet",
  });
});

// POST /api/v2/users/reset
router.post("/reset", (req: Request, res: Response) => {
  try {
    reset_users();
    return res.status(200).json({
      success: true,
      message: "User database has been reset",
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

export default router;