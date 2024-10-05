// config.js
module.exports = {
    mongodbURI: 'mongodb://localhost/emailAuthPractice',
    email: {
      service: 'gmail',
      user: 'maungkaungthukhant@gmail.com',
      pass: 'nlzbtvvqlbavenyy',
    },
    server: {
      url: process.env.SERVER_URL || 'http://localhost:8800'
    },
    secret: 'YOUR_SECRET_KEY',
  };