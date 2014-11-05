"use strict";

var seneca = require('seneca');

var assert = require('chai').assert;

var gex = require('gex');
var async = require('async');

var si = seneca();
si.use('..');

describe('user', function () {

  var salt;
  var pass;
  it('password-encryption', function (done) {
    this.timeout(60000)
    si.act('role:user,cmd:encrypt_password', {password: 'test',repeat: 'test'}, function(err,data){

      salt=data.salt;
      pass=data.pass;
      assert.isNull(err);
      assert.ok(data.ok);
      assert.isNotNull(data.salt);
      assert.equal(data.pass.length,172);

      done()
    });
  })

  it('verify-password', function (done) {
    this.timeout(60000)
    si.act('role:user,cmd:verify_password', {proposed: 'test',pass: pass,salt:salt}, function(err,data){
      assert.isNull(err);
      assert.ok(data.ok);


      done()
    });
  })
});
