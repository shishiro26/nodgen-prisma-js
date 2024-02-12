export const REGISTRATION_TEMPLATES = {
  subject: (projectName) => `Welcome to ${projectName} - Registration OTP`,
  text: (Username, projectName, otp) =>
    `Hello ${Username},\n\n` +
    `Thank you for choosing ${projectName}! You're just one step away from getting started.` +
    `Here's your OTP for registration:\n\n` +
    `OTP: ${otp}\n\n` +
    `Simply enter this OTP to complete your registration process.` +
    `If you have any questions or need assistance, feel free to contact us.\n\n` +
    `Best regards,\n` +
    `The ${projectName} Team`,
  html: (Username, projectName, otp) => `<html>
  <body style="font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0; ;">
   <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%"
     style="max-width: 600px; background-color: #ffffff; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); margin: 30px auto; border-radius: 4px;">
     <tr>
       <td style="padding: 30px; ">
         <table border="0" cellpadding="0" cellspacing="0" width="100%">
           <tr>
             <td>
               <div style="text-align: center;">
               <h1 style="color: rgb(8, 32, 169); user-select:none">${projectName}</h1>
               </div>
             </td>
           </tr>
           <tr>
             <td style="padding: 20px 0;">
               <p style="font-size: 18px; color: #333333;">Hello ${Username},</p>
               <p style="font-size: 16px; color: #666666;">Thank you for choosing ${projectName}! You're just one step
                 away from getting started.</p>
               <p style="font-size: 16px; color: #666666;">Here's your OTP for registration:</p>
               <p style="font-size: 20px; color: #333333;"><strong>${otp}</strong></p>
               <p style="font-size: 16px; color: #666666;">Best regards,<br>The ${projectName} Team</p>
             </td>
           </tr>
         </table>
       </td>
     </tr>
   </table>
 </body>
 
 </html>`,
};

export const RESET_PASSWORD = {
  subject: "Password Reset Requested!",
  text: (Username, projectName, otp) =>
    `Hello ${Username},\n\n` +
    `You have requested a password reset for your ${projectName} account.` +
    `OTP for Temporary Password: ${otp}\n\n` +
    `Please change your password after logging in for security reasons.` +
    `If you didn't request this password reset, please contact us immediately.` +
    `For additional security, this OTP will expire in 24 hours.\n\n` +
    `Best regards,\n` +
    `The ${projectName} Team`,

  html: (Username, projectName, otp) => `<html>
  <body style="font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0;">
    <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%"
      style="max-width: 600px; background-color: #ffffff; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); margin: 30px auto; border-radius: 5px;">
      <tr>
        <td style="padding: 30px;">
          <table border="0" cellpadding="0" cellspacing="0" width="100%">
            <tr>
              <td>
                <div style="text-align: center;">
                <h1 style="color: rgb(8, 32, 169); user-select:none">${projectName}</h1>
                </div>
              </td>
            </tr>
            <tr>
              <td>
                <p style="font-size: 18px; color: #333333;">Hello ${Username},</p>
                <p style="font-size: 16px; color: #666666;">You have requested a password reset for your ${projectName}
                  account.</p>
                <p style="font-size: 20px; color: #333333;">OTP for Temporary Password: <strong>${otp}</strong></p>
                <p style="font-size: 16px; color: #666666;">Please change your password after logging in for security
                  reasons.</p>
                <p style="font-size: 16px; color: #666666;">If you didn't request this password reset, please contact us
                  immediately.</p>
                <p style="font-size: 16px; color: #666666;">For additional security, this OTP will expire in 5 minutes.</p>
              </td>
            </tr>
            <tr>
              <td>
                <p style="font-size: 16px; color: #666666; margin-top: 20px;">Best regards,</p>
                <p style="font-size: 16px; color: #333333; font-weight: bold;">The ${projectName} Team</p>
              </td>
            </tr>
          </table>
        </td>
      </tr>
    </table>
  </body>
  
  </html>`,
};

export const RESEND_OTP = {
  subject: "Resend OTP",
  text: (Username, projectName, otp) =>
    `Hello ${Username},\n\n` +
    `You have requested to resend the OTP for your ${projectName} account.` +
    `Here's your OTP: ${otp}\n\n` +
    `Please use this OTP to complete your action.` +
    `If you didn't request this OTP, please ignore this email.` +
    `For security reasons, this OTP will expire in 5 minutes.\n\n` +
    `Best regards,\n` +
    `The ${projectName} Team`,

  html: (Username, projectName, otp) => `
  <html>
    <body style="font-family: Arial, sans-serif; background-color: #f2f2f2; margin: 0; padding: 0;">
      <table align="center" border="0" cellpadding="0" cellspacing="0" width="100%"
        style="max-width: 600px; background-color: #ffffff; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1); margin: 30px auto; border-radius: 5px;">
        <tr>
          <td style="padding: 30px;">
            <table border="0" cellpadding="0" cellspacing="0" width="100%">
              <tr>
                <td>
                  <div style="text-align: center;">
                    <h1 style="color: rgb(8, 32, 169); user-select: none;">${projectName}</h1>
                  </div>
                </td>
              </tr>
              <tr>
                <td>
                  <p style="font-size: 18px; color: #333333;">Hello ${Username},</p>
                  <p style="font-size: 16px; color: #666666;">You have requested to resend the OTP for your ${projectName} account.</p>
                  <p style="font-size: 20px; color: #333333;">Here's your OTP: <strong>${otp}</strong></p>
                  <p style="font-size: 16px; color: #666666;">Please use this OTP to complete your action.</p>
                  <p style="font-size: 16px; color: #666666;">If you didn't request this OTP, please ignore this email.</p>
                  <p style="font-size: 16px; color: #666666;">For security reasons, this OTP will expire in 5 minutes.</p>
                </td>
              </tr>
              <tr>
                <td>
                  <p style="font-size: 16px; color: #666666; margin-top: 20px;">Best regards,</p>
                  <p style="font-size: 16px; color: #333333; font-weight: bold;">The ${projectName} Team</p>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </body>
  </html>`,
};
