//D:\workspace\practice_lab16\src\db\db_transactions.ts
import * as fs from "fs/promises"; // For promise-based fs methods
// import * as path from "path";
import { type Student } from "../libs/types.js";

import { fileURLToPath } from "url";
import { dirname } from "path";

// Define __dirname for ES module scope
const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const DATA_FILE_PATH = `${__dirname}/db_students.json`;

export async function readDataFile(): Promise<Student[]> {
  try {
    console.log(DATA_FILE_PATH);
    const data = await fs.readFile(DATA_FILE_PATH, {
      encoding: "utf8",
    });
    return JSON.parse(data) as Student[];
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      console.warn("Data file not found, returning empty array.");
      return []; // Return empty array if file doesn't exist
    }
    console.error("Error reading data file:", error);
    throw error;
  }
}

export async function writeDataFile(data: Student[]): Promise<void> {
  try {
    const jsonString = JSON.stringify(data, null, 2); // null, 2 for pretty printing
    await fs.writeFile(DATA_FILE_PATH, jsonString, { encoding: "utf8" });
  } catch (error) {
    console.error("Error writing data file:", error);
    throw error;
  }
}
