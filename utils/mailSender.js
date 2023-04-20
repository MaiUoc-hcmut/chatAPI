const nodemailer = require('nodemailer');
const sendEmail = async (options) => {
    //1.Tạo trasporter
    const transporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST,
        port: process.env.EMAIL_PORT,
        auth: {
            user: process.env.EMAIL_USERNAME,
            pass: process.env.EMAIL_PASSWORD,
        },
        tls: {
            rejectUnauthorized: false,
        }
    })

    //2. Xác định các option cho mail
    const mailOptions = {
        from: 'Ha Duyen Thang',
        to: options.email,
        subject: options.subject,
        text: options.message,
    }

    //3. Gửi mail
    await transporter.sendMail(mailOptions);
}
module.exports = sendEmail;