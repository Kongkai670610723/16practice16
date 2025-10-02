//D:\workspace\practice_lab16\src\routes\enrollmentsRoutes_v2.ts
//ทำการ import Router, Request, Response
import { Router, type Request, type Response } from "express";          //pnpm install

//
import  jwt  from "jsonwebtoken";                                       //pnpm i -D @types/jsonwebtoken
import  dontenv  from "dotenv";                                         //pnpm i dotenv
dontenv.config();

//import type
import type { User, Student, UserPayload, CustomRequest, Enrollment } from "../libs/types.js";

// import database
import { users, reset_users } from "../db/db.js";
import { students } from "../db/db.js";
import { courses } from "../db/db.js";
import { enrollments, reset_enrollments } from "../db/db.js";

import { success } from "zod"; 
import { error } from "console";
import { authenticateToken } from "../middlewares/authenMiddleware.js";
import { checkRoleAdmin } from "../middlewares/checkRoleAdminMiddleware.js";            //Admin Roles
import { checkRoleStudent } from "../middlewares/checkRoleStudentMiddleware.js";        //Student Roles
import { checkAllRoles } from "../middlewares/checkAllRolesMiddleware.js";              //All Roles
import { zStudentId } from "../libs/zodValidators.js";
import { zEnrollmentBody } from "../libs/zodValidators.js";


const router = Router();

//GET   /api/v2/enrollments
router.get("/", authenticateToken, checkRoleAdmin, (req: CustomRequest,res: Response) => {
    try {
        const user_id = students.map((s: Student) =>{
            const students_Enrollments = enrollments
            .filter((ent: Enrollment) => ent.studentId === s.studentId)
            .map((ent: Enrollment) => ent.courseId);
            

            return {
                studentId: s.studentId,
                courses: students_Enrollments,
            };
        });

            return res.status(200).json({ 
                success: true,
                message: "Enrollments Information",
                data: user_id,
            });

    } catch (err) {
        return res.status(500).json({
            success: false,
            message: "Something is wrong, please try again",
            error: err,
        });
    }
});






// POST /api/v2/enrollments/reset
router.post("/reset", authenticateToken, checkRoleAdmin, (req: Request, res: Response) => {
  try {
    reset_enrollments();
    return res.status(200).json({
      success: true,
      message: "enrollments database has been reset",
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});







// GET  /api/v2/enrollments/:studentId
router.get("/:studentId", authenticateToken, (req: CustomRequest, res: Response) => {
    try {
      const studentId = req.params.studentId;
      const result = zStudentId.safeParse(studentId);

      if (!result.success) {
        return res.status(400).json({
          message: "Validation failed",
          errors: result.error.issues[0]?.message,
        });
      }

      const studentIndex = students.findIndex(
        (student: Student) => student.studentId === studentId
      );

      if (studentIndex === -1) {
        return res.status(404).json({
          success: false,
          message: "StudentId does not exists",
        });
      }

      const payload = req.user;
      const token = req.token;

      // 2. check if user exists (search with username) and role is ADMIN
      const user = users.find((u: User) => u.username === payload?.username);
      if (!user) {
        return res.status(401).json({
          success: false,
          message: "Unauthorized user",
        });
      }

      if (
        user.role === "ADMIN" ||
        (user.role === "STUDENT" && user.studentId === studentId)
      ) {

        const courseIds = enrollments
          .filter((en: Enrollment) => en.studentId === studentId)
          .map((en: Enrollment) => en.courseId);

        return res.status(200).json({
          success: true,
          message: "Student information",
          data: { studentId, courses: courseIds },
        });


      } else {
        return res.status(403).json({
          success: false,
          message: "Forbidden access",
        });
      }
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: "Something is wrong, please try again",
        error: err,
      });
    }
  }
);





//POST  /api/v2/enrollments/:studentId
router.post("/:studentId", authenticateToken, checkRoleStudent, (req: CustomRequest, res: Response) => {
    try {
      const studentId = req.params.studentId;
      const body = req.body as Enrollment;

      const result1 = zStudentId.safeParse(studentId);
      const result2 = zEnrollmentBody.safeParse(body);

      if (!result1.success) {
        return res.status(400).json({
          message: "Validation failed",
          errors: result1.error.issues[0]?.message,
        });
      }
      if (!result2.success) {
        return res.status(400).json({
          message: "Validation failed",
          errors: result2.error.issues[0]?.message,
        });
      }
      const studentIndex = students.findIndex(
        (student) => studentId === student.studentId
      );

      if (studentIndex === -1) {
        return res.status(404).json({
          success: false,
          message: "StudentId does not exists",
        });
      }
      const payload = req.user;
      const token = req.token;

      // 2. check if user exists (search with username) and role is ADMIN
      const user = users.find((u: User) => u.username === payload?.username);

      if (
        studentId != body.studentId ||
        user?.studentId != studentId ||
        user?.studentId != body.studentId
      ) {
        return res.status(403).json({
          success: false,
          message: "Forbidden access",
        });
      }
      console.log(body);

      const findenrollment = enrollments.find(
        (enroll: Enrollment) =>
          body.studentId === enroll.studentId &&
          body.courseId === enroll.courseId
      );

      if (findenrollment) {
        return res.status(409).json({
          success: false,
          message: "Enrollment is already exists",
        });
      }

      enrollments.push(body);
      const newcourse = enrollments
        .filter((enroll) => enroll.studentId === studentId)
        .map((enroll) => enroll.courseId);

      students[studentIndex] = {
        ...students[studentIndex],
        courses: newcourse,
      } as Student;


      const courseId = req.body.courseId;


      return res.status(200).json({
        success: true,
        message: `Student ${studentId} && Course ${courseId} has been added successfully`,
        data: {
          studentId: studentId,
          courseId: courseId
        }
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: "Something is wrong, please try again",
        error: err,
      });
    }
  }
);


//DELETE  /api/v2/enrollments/:studentId
router.delete("/:studentId", authenticateToken, checkRoleStudent, (req: CustomRequest, res: Response) => {
    try {
      const studentId = req.params.studentId;
      const body = req.body;

      const result1 = zStudentId.safeParse(studentId);
      const result2 = zEnrollmentBody.safeParse(body);

      if (!result1.success) {
        return res.status(400).json({
          message: "Validation failed",
          errors: result1.error.issues[0]?.message,
        });
      }
      if (!result2.success) {
        return res.status(400).json({
          message: "Validation failed",
          errors: result2.error.issues[0]?.message,
        });
      }

      const payload = req.user;
      const token = req.token;
      // 2. check if user exists (search with username) and role is ADMIN
      const user = users.find((u: User) => u.username === payload?.username);

      if (
        studentId != body.studentId ||
        user?.studentId != studentId ||
        user?.studentId != body.studentId
      ) {
        return res.status(403).json({
          success: false,
          message: "Forbidden access",
        });
      }

      const studentIndex = students.findIndex(
        (student) => student.studentId === studentId
      );

      if (studentIndex === -1) {
        return res.status(404).json({
          success: false,
          message: "StudentId does not exists",
        });
      }

      const enrollIndex = enrollments.findIndex(
        (enroll) =>
          enroll.studentId === studentId && enroll.courseId === body.courseId
      );
      if (enrollIndex === -1) {
        return res.status(404).json({
          success: false,
          message: "Enrollment does not exists",
        });
      }

      enrollments.splice(enrollIndex, 1);

      const newcourse = enrollments
        .filter((enroll) => enroll.studentId === studentId)
        .map((enroll) => enroll.courseId);

     students[studentIndex] = {...students[studentIndex] ,  courses:newcourse } as Student ;
      return res.status(200).json({
        success: true,
        message: `Student ${studentId} && Course ${body.courseId} has been deleted successfully`,
        data: enrollments,
      });
    } catch (err) {
      return res.status(500).json({
        success: false,
        message: "Something is wrong, please try again",
        error: err,
      });
    }
  }
);

export default router;