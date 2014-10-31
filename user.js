"use strict";


var crypto = require('crypto')

var _    = require('underscore')
var uuid = require('node-uuid')


module.exports = function user(options) {
  var seneca = this

  // # Plugin options.
  // These are the defaults. You can override using the _options_ argument.
  // Example: `seneca.use("user",{mustrepeat:true})`.
  options = seneca.util.deepextend({
    role:        'user',
    rounds:      11111,
    autopass:    true,    // generate a password if none provided
    mustrepeat:  false, // password repeat arg needed
    resetperiod: (24*60*60*1000), // must reset within this time period, default: 24 hours
    confirm:     false,
    user:{
      fields:[
        {name:'pass',hide:true},
        {name:'salt',hide:true}
      ]
    },
    login:{
      fields:[]
    },
    reset:{
      fields:[]
    }
  },options)


  // You can change the _role_ value for the plugin patterns.
  // Use this when you want to load multiple versions of the plugin
  // and expose them via different patterns.
  var role = options.role



  // # Action patterns
  // These define the pattern interface for this plugin.
  ;


  // ### Encrypt a plain text password string
  // Pattern: _**role**:user, **cmd**:encrypt_password_
  seneca.add({
    role: role,
    cmd:  'encrypt_password',

    password: {type:'string$'}, // password plain text string
    repeat:   {type:'string$'} // password plain text string, repeated
  }, cmd_encrypt_password )



  // ### Verify a password string
  // Pattern: _**role**:user, **cmd**:verify_password_
  // Has the user entered the correct password?
  seneca.add({
    role: role,
    cmd:  'verify_password',

    proposed: {required$:true,string$:true},
    pass:     {required$:true,string$:true},
    salt:     {required$:true,string$:true}
  }, cmd_verify_password )





  function hide(args,propnames){
    var outargs = _.extend({},args)
    for( var pn in propnames ) {
      outargs[pn] = '[HIDDEN]'
    }
    return outargs
  }


  // Encrypt password using a salt and multiple SHA512 rounds
  // Override for password strength checking
  // - password: password string
  // - repeat: password repeat, optional
  // Provides: {pass:,salt:,ok:,why:}
  // use why if password too weak
  function cmd_encrypt_password( args, done ){
    var password = void 0 == args.password ? args.pass : args.password
    var repeat   = args.repeat

    if( _.isUndefined( password ) ) {
      if( options.autopass ) {
        password = uuid()
      }
      else return seneca.fail({code:'user/no-password',whence:args.whence},done);
    }

    if( _.isUndefined( repeat ) ) {
      if( options.mustrepeat ) {
        return seneca.fail({code:'user/no-password-repeat',whence:args.whence},done);
      }
      else repeat = password
    }

    if( password !== repeat ) {
      return done(null,{ok:false,why:'password_mismatch',whence:args.whence})
    }


    var salt = uuid().substring(0,8)


    crypto.pbkdf2(args.password || '', salt,  options.rounds,128, function (err,pass) {
      if(err) done(err,null);
      done(null, {ok: true, pass: pass, salt: salt});
    });


  }
  cmd_encrypt_password.descdata = function(args){return hide(args,{password:1,repeat:1})}



  // Verify proposed password is correct, redoing SHA512 rounds
  // - proposed: trial password string
  // - pass:     password hash
  // - salt:     password salt
  // Provides: {ok:}
  function cmd_verify_password( args, done ){

    crypto.pbkdf2Sync(args.password, salt,  options.rounds,256, function (err,pass) {
      if(err) done(err,null);
      var ok = (pass === args.pass)

      // for backwards compatibility with <= 0.2.3
      if (!ok && options.oldsha) {
        var shasum = crypto.createHash('sha1')
        shasum.update(args.proposed + args.salt)
        pass = shasum.digest('hex')

        ok = (pass === args.pass)
        return done(null, {ok: ok});
      }
      else return done(null, {ok: ok});
    });

  }
  cmd_verify_password.descdata = function(args){return hide(args,{proposed:1})}



  // Change password using user's nick or email
  // - nick, email: to resolve user
  // - user: user entity
  // - password: new password
  // - repeat: password repeat, optional
  // Provides: {ok:,user:}
  function cmd_change_password( args, done ){
    var seneca = this
    var user = args.user

    seneca.act(
      { role:role, cmd:'encrypt_password', whence:'change/user='+user.id+','+user.nick,
        password: args.password, repeat: args.repeat },
      function( err, out ){
        if( err ) return done(err);
        if( !out.ok ) return done(null,out);

        user.salt = out.salt
        user.pass = out.pass
        user.save$(function(err,user){
          if( err ) return done(err);

          done(null,{ok:true,user:user})
        })
      })
  }
  cmd_change_password.descdata = function(args){return hide(args,{password:1,repeat:1})}

  seneca.add({init:role},function(args,done){
    var seneca  = this
    var userent = seneca.make('sys/user')
    var loginent = seneca.make('sys/login')
    var resetent = seneca.make('sys/reset')

    this.act('role:util, cmd:define_sys_entity', {list:[
      { entity:userent.entity$, fields:options.user.fields},
      { entity:loginent.entity$,fields:options.login.fields},
      { entity:resetent.entity$,fields:options.reset.fields}
    ]},done)
  })


  return {
    name:role
  }
}
