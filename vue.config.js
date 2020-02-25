module.exports = {
  outputDir: "dist",
  assetsDir: "static",
  devServer: {
    proxy: {
      "/api/*": {
        target: "http://localhost:8000/"
      }
    }
  }
};
