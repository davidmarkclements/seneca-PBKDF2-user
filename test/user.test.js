"use strict";

var seneca = require('seneca');

var assert = require('chai').assert;

var gex = require('gex');
var async = require('async');

var si = seneca();
si.use('..');

describe('user', function () {

  it('password-encryption', function (done) {
    this.timeout(60000)
    si.act('role:user,cmd:encrypt_password', {password: 'test',repeat: 'test'}, function(err,data){
      assert.isNull(err);
      assert.ok(data.ok);
      assert.isNotNull(data.salt);
      assert.equal(data.pass.length,128);

      done()
    });
  })
});
