'use strict'

const {key} = require('zeronet-crypto')

/**
 * A rule book defines which and how many keys can/have to sign
 * @namespace RuleBook
 * @param {Object} opt - Options
 * @constructor
 */
function RuleBook (opt) {
  const self = this

  if (!Array.isArray(opt.validKeys)) opt.validKeys = [opt.validKeys]

  self.validKeys = opt.validKeys
  self.signsRequired = opt.signsRequired || 1

  self.isKeyAllowed = key => self.validKeys.indexOf(key) !== -1
  self.getSignsRequired = () => self.signsRequired
  self.getValidKeys = () => self.validKeys

  self.verifyManyToOne = (data, sig) => { // many keys can sign, only one signed
    return Boolean(self.getValidKeys().filter(adr => key.verify(adr, data, sig)).length)
  }

  self.verifyManyToMany = (data, signs) => { // many keys can sign, one/many need to sign. signs is a adr=>sign object
    const sigs = self.getValidKeys().filter(adr => signs[adr]).map(adr => {
      return {
        adr,
        sign: signs[adr]
      }
    })
    if (sigs.length < self.getSignsRequired()) throw new Error(sigs.length + ' signatures found but ' + self.getSignsRequired() + ' is/are needed')
    const vsigs = sigs.filter(sig => key.verify(sig.adr, data, sig.sign))
    if (vsigs.length < self.getSignsRequired()) throw new Error(vsigs.length + ' valid signatures out of ' + sigs.length + ' found but ' + self.getSignsRequired() + ' is/are needed')
    return true
  }
}

module.exports = RuleBook
