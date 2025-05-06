require('dotenv').config();
const { MongoClient } = require('mongodb');

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;

const atlasURI = `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/?retryWrites=true`;

const database = new MongoClient(atlasURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

database.connect()
  .then(() => {
    console.log("Connected to MongoDB!");
  })
  .catch(err => {
    console.error("Failed to connect to MongoDB: ", err);
});

module.exports = {database};