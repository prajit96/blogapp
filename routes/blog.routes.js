const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const Blog = require('../models/blog.model');
const User = require('../models/user.model');

const authenticateUser = (req, res, next) => {
  try {
    const token = req.headers.authorization.split(' ')[1];
    const decodedToken = jwt.verify(token, 'secretKey');
    req.userData = { userId: decodedToken.userId };
    next();
  } catch (error) {
    res.status(401).json({ message: 'Authentication failed' });
  }
};

router.get('/blogs', authenticateUser, async (req, res) => {
  try {
    const blogs = await Blog.find();
    res.status(200).json(blogs);
  } catch (error) {
    res.status(500).json({ message: 'Failed to fetch blogs' });
  }
});

router.post('/blogs', authenticateUser, async (req, res) => {
  try {
    const { title, content, category } = req.body;
    const username = await User.findById(req.userData.userId).select('username');
    const newBlog = new Blog({
      username: username.username,
      title,
      content,
      category,
    });
    await newBlog.save();
    res.status(201).json({ message: 'Blog created successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to create blog' });
  }
});

router.put('/blogs/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const { title, content, category } = req.body;
    const updatedBlog = await Blog.findByIdAndUpdate(
      id,
      { title, content, category },
      { new: true }
    );
    if (!updatedBlog) {
      return res.status(404).json({ message: 'Blog not found' });
    }
    res.status(200).json({ message: 'Blog updated successfully', blog: updatedBlog });
  } catch (error) {
    res.status(500).json({ message: 'Failed to update blog' });
  }
});

router.delete('/blogs/:id', authenticateUser, async (req, res) => {
  try {
    const { id } = req.params;
    const deletedBlog = await Blog.findByIdAndDelete(id);
    if (!deletedBlog) {
      return res.status(404).json({ message: 'Blog not found' });
    }
    res.status(200).json({ message: 'Blog deleted successfully' });
  } catch (error) {
    res.status(500).json({ message: 'Failed to delete blog' });
  }
});

router.patch('/blogs/:id/like', authenticateUser, async (req, res) => {
    try {
      const { id } = req.params;
      const updatedBlog = await Blog.findByIdAndUpdate(
        id,
        { $inc: { likes: 1 } },
        { new: true }
      );
      if (!updatedBlog) {
        return res.status(404).json({ message: 'Blog not found' });
      }
      res.status(200).json({ message: 'Blog liked successfully', blog: updatedBlog });
    } catch (error) {
      res.status(500).json({ message: 'Failed to like blog' });
    }
  });
  
  router.patch('/blogs/:id/comment', authenticateUser, async (req, res) => {
    try {
      const { id } = req.params;
      const { content } = req.body;
      const username = await User.findById(req.userData.userId).select('username');
      
      const updatedBlog = await Blog.findByIdAndUpdate(
        id,
        { $push: { comments: { username: username.username, content } } }, 
        { new: true }
      );
      if (!updatedBlog) {
        return res.status(404).json({ message: 'Blog not found' });
      }
      res.status(200).json({ message: 'Comment added successfully', blog: updatedBlog });
    } catch (error) {
      res.status(500).json({ message: 'Failed to add comment' });
    }
  });

module.exports = router;