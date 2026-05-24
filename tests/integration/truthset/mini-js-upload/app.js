/**
 * Mini Express/multer upload app — planted upload vulnerabilities for truth-set.
 */
const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');

const app = express();

// -----------------------------------------------------------------------
// PLANTED BUG 1 (lines 13-25):
// multer({ dest: 'public/uploads/' }) with no fileFilter
// Any file type is accepted and stored in a publicly-served directory
// -----------------------------------------------------------------------
const uploadNoFilter = multer({ dest: 'public/uploads/' });   // line 13

app.post('/upload1', uploadNoFilter.single('file'), (req, res) => {   // line 15
  // No fileFilter — all file types accepted including .php, .exe
  const file = req.file;
  if (!file) return res.status(400).send('no file');
  res.json({ message: 'uploaded', path: file.path });
});                                                             // line 21


// -----------------------------------------------------------------------
// PLANTED BUG 2 (lines 26-38):
// req.file.originalname written into a publicly-served path (path traversal)
// -----------------------------------------------------------------------
const storage = multer.diskStorage({
  destination: 'public/files/',                                // line 28
  filename: (req, file, cb) => {
    cb(null, file.originalname);    // attacker-controlled filename   line 30
  },
});
const uploadOriginalName = multer({ storage });

app.post('/upload2', uploadOriginalName.single('file'), (req, res) => {   // line 35
  res.json({ saved: req.file.originalname });
});                                                             // line 37


// -----------------------------------------------------------------------
// PLANTED BUG 3 (lines 42-55):
// No `limits` option — no size cap, DoS possible
// Filename from req.files served at a public path
// -----------------------------------------------------------------------
const uploadNoLimits = multer({ dest: 'uploads/' });           // line 42

app.post('/upload3', uploadNoLimits.array('files', 20), (req, res) => {   // line 44
  // No size limit, attacker can upload arbitrarily large files
  const files = req.files;
  const saved = files.map(f => ({
    original: f.originalname,
    path: f.path,
  }));
  res.json(saved);                                             // line 51
});


// -----------------------------------------------------------------------
// NEGATIVE CASE (lines 57-80):
// Proper: fileFilter + limits + UUID rename + outside-webroot storage
// -----------------------------------------------------------------------
const { v4: uuidv4 } = require('uuid');

const safeStorage = multer.diskStorage({
  destination: '/var/data/uploads/',                           // outside webroot
  filename: (req, file, cb) => {
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, uuidv4() + ext);                                  // server-generated name
  },
});

const ALLOWED_TYPES = ['image/png', 'image/jpeg', 'image/gif'];
const uploadSafe = multer({
  storage: safeStorage,
  limits: { fileSize: 10 * 1024 * 1024 },                    // 10 MB
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_TYPES.includes(file.mimetype)) {
      return cb(new Error('Invalid file type'), false);
    }
    cb(null, true);
  },
});

app.post('/upload_safe', uploadSafe.single('file'), (req, res) => {   // line 78
  res.json({ id: req.file.filename });
});                                                             // line 80

module.exports = app;
