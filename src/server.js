const { createApp } = require('./app');

const port = Number.parseInt(process.env.PORT || '3000', 10);
const app = createApp();

app.createServer().listen(port, () => {
  console.log(`iPhone agent backend listening on port ${port}`);
});
