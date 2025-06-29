import express from "express";
import mysql from "mysql";
import cors from "cors";
import cookieParser from "cookie-parser";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import multer from "multer";
import path from "path";
import dotenv from "dotenv";
dotenv.config(); // Load .env variables

const app = express();
app.use(cookieParser());

app.use(
  cors({
    origin: ["https://ehrsystemsite.netlify.app"],
    credentials: true,
    methods: ["POST", "GET", "PUT", "DELETE"],
  })
);

app.use(express.json());
app.use(express.static("public"));

// Configure connection pool
const pool = mysql.createPool({
  connectionLimit: 5, // Adjust the limit as per your needs
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  connectTimeout: 30000,  // Increase timeout to 30 seconds
  timeout: 30000          // Set connection timeout
});

// Helper function to query using the connection pool
const query = (sql, values = []) =>
  new Promise((resolve, reject) => {
    pool.query(sql, values, (err, results) => {
      if (err) return reject(err);
      resolve(results);
    });
  });

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, "./public/images");
  },
  filename: (req, file, cb) => {
    cb(null, file.fieldname + "_" + Date.now() + path.extname(file.originalname));
  },
});

const upload = multer({
  storage: storage,
});



// ===== admin ===== 
// register new user 
const saltRounds = 10;
app.post("/register", upload.single("photo"), async (req, res) => {
  const { name, email, role, password } = req.body;
  const photo = req.file?.filename || null;

  if (!name || !email || !role || !password) {
    return res.json({ Status: "Error", message: "All fields are required." });
  }

  try {
    const searchSql = "SELECT * FROM users WHERE email = ?";
    const results = await query(searchSql, [email]);

    if (results.length > 0) {
      return res.json({
        Status: "Exists",
        message: "User already exists. Please log in.",
      });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    const sql =
      "INSERT INTO users (name, email, role, photo, password) VALUES (?)";
    const values = [name, email, role, photo, hashedPassword];
    await query(sql, [values]);
    res.json({
      Status: "Success",
      message: "User Successfully Registered!",
    });
  } catch (error) {
    console.error("Failed to register new user", error);
    res.status(500).json({ message: "Signup failed", error });
  }
});

// ===== login ===== 
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  
  try {
    const searchSql = "SELECT * FROM users WHERE email = ?";
    const users = await query(searchSql, [email]);

    if (users.length === 0) {
      return res.status(401).json({ Status: "Error", message: "User not found, please register" });
    }

    const user = users[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(401).json({ Status: "Error", message: "Incorrect Password!" });
    }

    const token = jwt.sign(
      {
        id: user.id,
        name: user.name,
        email: user.email,
        photo: user.photo,
        role: user.role
      },
      "jwt-secret-key",
      { expiresIn: "1d" }
    );

    res.cookie("token", token, { httpOnly: true });
    res.json({
      Status: "Success",
      message: "Login Successful!",
      token,
      user: {
        id: user.id,
        name: user.name,
        email: user.email,
        photo: user.photo,
        role: user.role,
      },
    });
  } catch (error) {
    console.error("Failed to login", error);
    res.status(500).json({ Status: "Error", message: "An error occurred during login." });
  }
});

// protecting routes 
const verifyToken = (req, res, next) =>{
  const token = req.header("Authorization");
  console.log("Extracted Token:", token);

  if(!token){
    console.log("Token Missing");
    return res.status(403).json({error: "User not authenticated!"});
  }
  try {
    const verified = jwt.verify(token.split(" ")[1], "jwt-secret-key");
    req.user = verified;
    req.role = verified.role;
    console.log("Decoded Token:", verified);
    next();
  } catch (error) {
    res.status(400).json({error: "Invalid token"});
  }
}

// protected route admin 
app.get("/admin", verifyToken, (req, res) =>{
  res.json({Status: "success", role: req.role, message: "Protected route accessed", user: req.user})
})

// protected route doctor
app.get("/doctor", verifyToken, (req, res) =>{
  res.json({Status: "success", role: req.role, message: "Protected route accessed", user: req.user})
})

// protected route patient
app.get("/patient", verifyToken, (req, res) =>{
  res.json({Status: "success", role: req.role, message: "Protected route accessed", user: req.user})
})

// fetch all appointments 
app.get("/allAppointments", async (req, res) => {
  try {
    const sql = `
      SELECT
        a.id AS appointment_id,
        a.patient_id,
        a.doctor_id,
        a.appointment_date,
        a.department,
        a.procedure,
        a.status,
        a.date,
        u.id,
        u.name,
        u.photo
      FROM appointments a
      JOIN users u ON a.patient_id = u.id
    `;
    const result = await query(sql);
    res.status(200).json({ Result: result });
  } catch (error) {
    console.error("Failed to fetch appointments:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ===== doctor ===== 
// get doctors 
app.get("/doctors", async (req, res) => {
  try {
    const sql = "SELECT * FROM users WHERE role = 'Doctor' ORDER BY id DESC";
    const results = await query(sql);
    res.json({ Result: results });
  } catch (error) {
    console.error("Failed to fetch doctors", error);
    res.status(500).json({ message: "Failed to fetch doctors" });
  }
});

// get all user/doctor scheduled appointments 
app.get("/doctorAppointments/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const sql = `
      SELECT
        u.id,
        u.name,
        u.age,
        u.gender,
        u.phone,
        u.email,
        u.photo,
        a.id,
        a.appointment_date,
        a.department,
        a.procedure,
        a.status,
        a.patient_id,
        a.date
      FROM appointments a
      JOIN users u ON a.patient_id = u.id
      WHERE a.doctor_id = ? AND a.status = 'Scheduled'
    `;
    const result = await query(sql, [id]);
    res.status(200).json({ Result: result });
  } catch (error) {
    console.error("Failed to fetch appointments:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// get all user/doctor appointments 
app.get("/allDoctorAppointments/:id", async (req, res) => {
  const { id } = req.params;
  try {
    const sql = `
      SELECT
        u.id,
        u.name,
        u.age,
        u.gender,
        u.phone,
        u.email,
        u.photo,
        a.id,
        a.appointment_date,
        a.department,
        a.procedure,
        a.status,
        a.patient_id,
        a.date
      FROM appointments a
      JOIN users u ON a.patient_id = u.id
      WHERE a.doctor_id = ?
    `;
    const result = await query(sql, [id]);
    res.status(200).json({ Result: result });
  } catch (error) {
    console.error("Failed to fetch appointments:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// update appointment status
app.put('/updateAppointmentStatus/:id', async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  try {
    const sql = 'UPDATE appointments SET status = ? WHERE id = ?'
    await query(sql, [status, id]);
    res.json({ success: true, message: "Appointment successfully updated." });
  } catch (error) {
    console.error("Failed to update appointment status", error);
    res.status(500).json({ success: false, message: "Failed to update appointment status" });
  }
});


// adding lab results 
app.post("/labResults", async(req, res) =>{
  const { patientId, testName, labResults } = req.body;

  if (!patientId || !testName || !labResults) {
  return res.status(400).json({
    Status: "Error",
    message: "All fields are required.",
  });
}

  try {
    const sql = `INSERT INTO  labresults (patient_id, test_name, results) VALUES (?)`
    const values = [patientId, testName, labResults];
    await query(sql, [values])
     res.json({
      Status: "Success",
      message: "Lab Results Successfully Created!",
    });
  } catch (error) {
      console.error("Failed to create lab results", error);
    res.status(500).json({ Status: "Error", message: "An error occurred while creating lab results." });
  }
})

// fetch lab results 
app.get("/labResults", async(req, res) =>{
  try {
    const sql = `
    SELECT
    u.id,
    u.name,
    u.photo,
    l.patient_id,
    l.test_name,
    l.results,
    l.date,
    l.id AS lab_id
     FROM labresults l
      JOIN users u ON l.patient_id = u.id
      ORDER BY id DESC
    `
     const result = await query(sql);
    res.status(200).json({ Result: result });
  } catch (error) {
     console.error("Failed to fetch lab results:", error);
    res.status(500).json({ error: "Internal server error" });
  }
})



// ===== patients ===== 
// create appointments 
app.post("/appointment", async(req, res) =>{
  const {date, department, doctorId, procedure, patientId} = req.body;

  try {
    const sql = "INSERT INTO appointments (patient_id, doctor_id, appointment_date, department, `procedure`) VALUES (?)"
    const values = [patientId, doctorId, date, department, procedure]
    await query(sql, [values])
       res.json({
      Status: "Success",
      message: "Appointment Successfully Created!",
    });
    
  } catch (error) {
      console.error("Failed to create appointment", error);
    res.status(500).json({ Status: "Error", message: "An error occurred while creating appointment." });
  }
})


// get all user/patient appointments 
app.get("/patientAppointments/:id", async (req, res) => {
  const { id } = req.params;

  try {
    const sql = `
      SELECT
        u.id AS doctor_id,
        u.name,
        u.photo,
        a.id,
        a.appointment_date,
        a.department,
        a.procedure,
        a.status,
        a.date
      FROM appointments a
      JOIN users u ON a.doctor_id = u.id
      WHERE a.patient_id = ?
    `;
    const result = await query(sql, [id]);
    res.status(200).json({ Result: result });
  } catch (error) {
    console.error("Failed to fetch appointments:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// get doctor appointments 
app.get("/appointments", async (req, res) => {
  try {
    const sql = `
      SELECT
        a.id AS appointment_id,
        a.patient_id,
        a.doctor_id,
        a.appointment_date,
        a.department,
        a.procedure,
        a.status,
        a.date,
        u.id AS doctor_id,
        u.name AS doctor_name,
        u.photo AS doctor_photo
      FROM appointments a
      JOIN users u ON a.doctor_id = u.id
    `;
    const result = await query(sql);
    res.status(200).json({ Result: result });
  } catch (error) {
    console.error("Failed to fetch appointments:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// fetch all patients 
app.get("/patients", async (req, res) => {
  try {
    const sql = "SELECT * FROM users WHERE role = 'Patient' ORDER BY id DESC";
    const results = await query(sql);
    res.json({ Result: results });
  } catch (error) {
    console.error("Failed to fetch patients", error);
    res.status(500).json({ message: "Failed to fetch patients" });
  }
});

// fetch appointment details 
app.get("/appointmentDetails/:id", async(req, res) =>{
  const {id} = req.params;
  try {
    const sql = `
      SELECT
        u.id AS doctor_id,
        u.name,
        u.photo,
        a.id,
        a.appointment_date,
        a.department,
        a.procedure,
        a.status,
        a.patient_id,
        a.date
      FROM appointments a
      JOIN users u ON a.patient_id = u.id
      WHERE a.id = ?
    `;
    const result = await query(sql, [id]);
    res.status(200).json({ Result: result });
  } catch (error) {
    console.error("Failed to fetch appointments:", error);
    res.status(500).json({ error: "Internal server error" });
  }
})


// patient lab results 
app.get("/patientResults/:id", async(req, res) =>{
  const {id} = req.params;

  try {
    const sql = `
    SELECT
    u.id,
    u.name,
    u.photo,
    l.patient_id,
    l.test_name,
    l.results,
    l.date
     FROM labresults l
      JOIN users u ON l.patient_id = u.id
      WHERE l.patient_id = ?
      ORDER BY id DESC
    `
     const result = await query(sql, id);
    res.status(200).json({ Result: result });
  } catch (error) {
     console.error("Failed to fetch lab results:", error);
    res.status(500).json({ error: "Internal server error" });
  }
})







// port number 
const PORT = process.env.PORT || 8081;
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
