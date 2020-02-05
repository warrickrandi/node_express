const sum = (a, b) => {
  if (a && b) {
    return a + b;
  }

  throw new Error("invalid arguments");
};

console.log(sum(1));
