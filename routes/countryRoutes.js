// routes/countryRoutes.js
const express = require('express');
const router  = express.Router();
const { getAllCountries } = require('../controller/countryController');

// GET /country → returns all countries
router.get('/getAll', getAllCountries);

module.exports = router;
