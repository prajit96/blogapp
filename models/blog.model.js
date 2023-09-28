
const mongoose = require('mongoose');

const blogSchema = mongoose.Schema({
  username: { type: String, required: true },
  title: { type: String, required: true },
  content: { type: String, required: true },
  category: { type: String, required: true },
  date: { type: Date, default: Date.now },
  likes: { type: Number, default: 0 },
  comments: [{ username: String, content: String }],
});

module.exports = mongoose.model('Blog', blogSchema);