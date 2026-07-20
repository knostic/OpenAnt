const express = require("express");
const { getUser, createUser } = require("./db");

const app = express();
app.use(express.json());

app.get("/users/:id", async (req, res) => {
  const user = await getUser(req.params.id);
  if (!user) {
    return res.status(404).json({ error: "Not found" });
  }
  res.json(user);
});

app.post("/users", async (req, res) => {
  const { name } = req.body;
  if (!name) {
    return res.status(400).json({ error: "Name required" });
  }
  const user = await createUser(name);
  res.status(201).json(user);
});

module.exports = app;
