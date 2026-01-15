const pkg = require("../dist/cjs/index.js");
test("CJS import works", () => {
  expect(typeof pkg.XHDWalletAPI).toBe("function");
});