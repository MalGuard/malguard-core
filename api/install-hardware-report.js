'use strict';
// The unauthenticated legacy email path is permanently retired.
module.exports = async function handler(req,res) {
  res.setHeader('Cache-Control','no-store');
  return res.status(410).json({ok:false,error:'legacy-report-retired'});
};
