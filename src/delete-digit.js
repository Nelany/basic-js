const { NotImplementedError } = require('../extensions/index.js');

/**
 * Given some integer, find the maximal number you can obtain
 * by deleting exactly one digit of the given number.
 *
 * @param {Number} n
 * @return {Number}
 *
 * @example
 * For n = 152, the output should be 52
 *
 */
function deleteDigit(n) {
  const strNum = n.toString();
  let maxNum = 0;

  for (let i = 0; i < strNum.length; i++) {
    const modifiedNum = parseInt(strNum.slice(0, i) + strNum.slice(i + 1));
    maxNum = Math.max(maxNum, modifiedNum);
  }

  return maxNum;
}

module.exports = {
  deleteDigit
};
