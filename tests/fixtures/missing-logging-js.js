// JS file with logging configured but sensitive ops without log calls
// This should trigger the missing-logging check

const winston = require('winston');
const db = require('./db');

const logger = winston.createLogger({ level: 'info' });

async function authenticate(username, password) {
  const user = await db.findOne({ username });
  if (user && await user.comparePassword(password)) {
    return user;
  }
  return null;
}

async function deleteUser(userId) {
  await db.deleteOne({ _id: userId });
}

async function resetPassword(userId, newPassword) {
  const hashed = await hashPassword(newPassword);
  await db.updateOne({ _id: userId }, { password: hashed });
}
