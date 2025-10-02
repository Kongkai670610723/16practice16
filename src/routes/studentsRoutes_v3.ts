//D:\workspace\practice_lab16\src\routes\studentsRoutes_v3.ts
import { Router, type Request, type Response } from "express";
import {
  zStudentPostBody,
  zStudentPutBody,
  zStudentId,
} from "../libs/zodValidators.js";

import type { Student } from "../libs/types.js";

import notFoundMiddleware from "../middlewares/notFoundMiddleware.js";

// import database
import { readDataFile, writeDataFile } from "../db/db_transactions.js";

const router = Router();

// GET /api/v2/students
// get students (by program)
router.get("/", async (req: Request, res: Response) => {
  try {
    const students = await readDataFile();

    const program = req.query.program;

    if (program) {
      let filtered_students = students.filter(
        (student) => student.program === program
      );
      return res.json({
        success: true,
        data: filtered_students,
      });
    } else {
      return res.json({
        success: true,
        data: students,
      });
    }
  } catch (err) {
    return res.json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

// GET /api/v2/students/{studentId}
router.get("/:studentId", async (req: Request, res: Response) => {
  try {
    const students = await readDataFile();

    const studentId = req.params.studentId;
    const result = zStudentId.safeParse(studentId);

    if (!result.success) {
      return res.status(400).json({
        message: "Validation failed",
        errors: result.error.issues[0]?.message,
      });
    }

    const foundIndex = students.findIndex(
      (std: Student) => std.studentId === studentId
    );

    if (foundIndex === -1) {
      return res.status(404).json({
        success: false,
        message: "Student does not exists",
      });
    }

    res.json({
      success: true,
      data: students[foundIndex],
    });
  } catch (err) {
    return res.json({
      success: false,
      message: "Something is wrong, please try again",
      error: err,
    });
  }
});

// POST /api/v2/students, body = {new student data}
// add a new student
router.post("/", async (req: Request, res: Response) => {
  try {
    const students = await readDataFile();

    const body = req.body as Student;

    // validate req.body with predefined validator
    const result = zStudentPostBody.safeParse(body); // check zod
    if (!result.success) {
      return res.status(400).json({
        message: "Validation failed",
        errors: result.error.issues[0]?.message,
      });
    }

    //check duplicate studentId
    const found = students.find(
      (student) => student.studentId === body.studentId
    );
    if (found) {
      return res.status(400).json({
        success: false,
        message: "Student is already exists",
      });
    }

    // add new student and write to DB
    const new_student = body;
    students.push(new_student);
    await writeDataFile(students);

    // add response header 'Link'
    res.set("Link", `/students/${new_student.studentId}`);

    return res.status(201).json({
      success: true,
      data: new_student,
    });
    // return res.json({ ok: true, message: "successfully" });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Somthing is wrong, please try again",
      error: err,
    });
  }
});

// PUT /api/v2/students, body = {studentId}
// Update specified student
router.put("/", async (req: Request, res: Response) => {
  try {
    const students = await readDataFile();

    const body = req.body as Student;

    // validate req.body with predefined validator
    const result = zStudentPutBody.safeParse(body); // check zod
    if (!result.success) {
      return res.status(400).json({
        message: "Validation failed",
        errors: result.error.issues[0]?.message,
      });
    }

    //check duplicate studentId
    const foundIndex = students.findIndex(
      (student) => student.studentId === body.studentId
    );

    if (foundIndex === -1) {
      return res.status(404).json({
        success: false,
        message: "Student does not exists",
      });
    }

    // update student data
    students[foundIndex] = { ...students[foundIndex], ...body };
    await writeDataFile(students);

    // add response header 'Link'
    res.set("Link", `/students/${body.studentId}`);

    return res.status(200).json({
      success: true,
      message: `Student ${body.studentId} has been updated successfully`,
      data: students[foundIndex],
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Somthing is wrong, please try again",
      error: err,
    });
  }
});

// DELETE /api/v2/students, body = {studentId}
router.delete("/", async (req: Request, res: Response) => {
  try {
    const students = await readDataFile();

    const body = req.body;
    const parseResult = zStudentId.safeParse(body.studentId);

    if (!parseResult.success) {
      return res.status(400).json({
        success: false,
        message: "Validation failed",
        error: parseResult.error.issues[0]?.message,
      });
    }

    const foundIndex = students.findIndex(
      (std: Student) => std.studentId === body.studentId
    );

    console.log(foundIndex);
    if (foundIndex === -1) {
      return res.status(404).json({
        success: false,
        message: "Student does not exists",
      });
    }

    // delete found student from array
    students.splice(foundIndex, 1);
    await writeDataFile(students);

    res.json({
      success: true,
      message: `Student ${body.studentId} has been deleted successfully`,
    });
  } catch (err) {
    return res.status(500).json({
      success: false,
      message: "Somthing is wrong, please try again",
      error: err,
    });
  }
});

export default router;
