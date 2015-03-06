"use strict";


var crypto = require('crypto')
var _    = require('underscore')
var uuid= require('node-uuid')



function conditionalExtend(user, args) {
  var extra = _.omit(args,[
    'role','cmd','nick','email','name','active','username','password','rounds','salt','pass','id','confirmed','confirmcode'
  ])
  _.map(extra,function(val,key){
    if( !key.match(/\$/) ) {
      user[key]=val
    }
  })
}

module.exports = function user(options) {
  var seneca = this

  // # Plugin options.
  // These are the defaults. You can override using the _options_ argument.
  // Example: `seneca.use("user",{mustrepeat:true})`.
  options = seneca.util.deepextend({
    role:        'user',
    autopass:    true,    // generate a password if none provided
    mustrepeat:  false, // password repeat arg needed
    resetperiod: (24*60*60*1000), // must reset within this time period, default: 24 hours
    confirm:     false,
    keylenght:   128,
    saltlenght:  256,
    rounds:      11111,
    user:{
      fields:[
        {name:'pass',hide:true},
        {name:'salt',hide:true},
        {name:'rounds',hide:true}
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
    salt:     {required$:true,string$:true},
    rounds:   {required$:true,string$:true}
  }, cmd_verify_password )



  // ### Register a new user
  // Pattern: _**role**:user, **cmd**:register_
  seneca.add({
    role: role,
    cmd:  'register',

    // identify user, various options
    atleastone$: ['nick','email','username'],
    nick:        {string$:true},
    email:       {string$:true},
    username:    {string$:true},

    password:    {string$:true},  // password plain text string
    repeat:      {string$:true},  // password plain text string, repeated

    name:        {string$:true},  // full name, as one string
    active:      {boolean$:true}, // is user active?

    confirm:     {boolean$:true} // is user confirmed?
  }, cmd_register )

  // ### Login a user
  // Pattern: _**role**:user, **cmd**:login_
  // Creates an entry in _sys/login_ and generates a login token
  seneca.add({
    role:role,
    cmd:'login',

    // identify user, various options
    atleastone$:['nick','email','user','username'],
    nick:     {string$:true},
    email:    {string$:true},
    username: {string$:true},
    user:     {object$:true},

    password: {string$:true}, // password plain text
    auto:     {boolean$:true} // login without password

  }, resolve_user(cmd_login,false) )



  function hide(args,propnames){
    var outargs = _.extend({},args)
    for( var pn in propnames ) {
      outargs[pn] = '[HIDDEN]'
    }
    return outargs
  }

  // Login an existing user - generates a login token. User must be active
  // - nick, email: to resolve user
  // - user:     user entity
  // - password: password text, alias: pass
  // Provides:
  // - success: {ok:true,user:,login:}
  // - failure: {ok:false,why:,nick:}
  function cmd_login(args,done){
    var seneca = this, user = args.user, why;
    var loginent = seneca.make('sys/login')


    if( !user.active ) {
      seneca.log.debug('login/fail',why='not-active', user)
      return done(null,{ok:false,why:why,user:user})
    }

    if( args.auto ) {
      return make_login( user, 'auto' );
    }
    else {
      seneca.act({role:role,cmd:'verify_password',proposed:args.password,pass:user.pass,salt:user.salt,rounds:user.rounds}, function(err,out){
        if( err ) return done(err);
        if( !out.ok ) {
          seneca.log.debug('login/fail',why='invalid-password',user)
          return done(null,{ok:false,why:why})
        }
        else return make_login( user, 'password' );
      })
    }


    function make_login( user, why ) {
      var cleanargs = seneca.util.clean(_.clone(args))

      var login = loginent.make$( seneca.util.argprops(
        {},
        cleanargs,
        {
          id$     : ab2str(crypto.randomBytes(15)),
          nick    : user.nick,
          user    : user.id,
          when    : new Date().toISOString(),
          active  : true,
          why     : why
        },
        "role,cmd,password"))

      login.token = login.id$, // DEPRECATED

        login.save$( function( err, login ){
          if( err ) return done(err);

          seneca.log.debug('login/ok',why,user,login)
          done(null,{ok:true,user:user,login:login,why:why})
        })
    }
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
        password = ab2str(crypto.randomBytes(options.saltlenght))
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


    var salt = ab2str(crypto.randomBytes(options.saltlenght))


    crypto.pbkdf2(args.password || '', salt,  options.rounds,options.keylenght, function (err,pass) {
      if(err) done(err,null);
      done(null, {ok: true, pass: ab2str(pass), salt: salt, rounds : options.rounds.toString()});
    });


  }
  cmd_encrypt_password.descdata = function(args){return hide(args,{password:1,repeat:1})}

  function ab2str(buf) {
    return buf.toString('base64');
  }

  // Verify proposed password is correct, redoing SHA512 rounds
  // - proposed: trial password string
  // - pass:     password hash
  // - salt:     password salt
  // Provides: {ok:}
  function cmd_verify_password( args, done ){

    crypto.pbkdf2(args.proposed|| '', args.salt,  parseInt(args.rounds),options.keylenght, function (err,pass) {
      if(err) done(err,null);
      var ok = (ab2str(pass) === args.pass);
      return done(null, {ok: ok});
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
        user.rounds = options.rounds

        user.save$(function(err,user){
          if( err ) return done(err);

          done(null,{ok:true,user:user})
        })
      })
  }
  cmd_change_password.descdata = function(args){return hide(args,{password:1,repeat:1})}



  // Register a new user
  // - nick:     username, data store should ensure unique, alias: username, email used if not present
  // - email:    primary email address, data store should ensure unique
  // - name:     full name of user
  // - active:   status of user, active==true means login succeeds
  // - password: password text, alias: pass
  // - confirmed:  user already confirmed, default: false
  // Generated fields:
  // - when: date and time of registration
  // - confirmcode: used for confirmation
  // Provides:
  // - success: {ok:true,user:}
  // - failure: {ok:false,why:,nick:}
  function cmd_register(args,done){
    var seneca  = this
    var userent = seneca.make('sys/user')
    var user    = userent.make$()

    user.nick     = args.nick || args.username || args.email
    user.email    = args.email
    user.name     = args.name || ''
    user.active   = void 0==args.active ? true : args.active
    user.when     = new Date().toISOString()

    if( options.confirm ) {
      user.confirmed = args.confirmed || false
      user.confirmcode = uuid()
    }

    conditionalExtend(user, args)

    var exists = false

    return checknick(
      function(){ checkemail(
        function() { saveuser() })});

    // unsafe nick unique check, data store should also enforce !!
    function checknick(next) {
      if( user.nick ) {
        userent.load$({nick:user.nick},function(err,userfound){
          if( err ) return done(err,{ok:false,user:user})
          if( userfound ) return done(null,{ok:false,why:'nick-exists',nick:args.nick})
          next()
        })
        return
      }
      next()
    }

    // unsafe email unique check, data store should also enforce !!
    function checkemail(next) {
      if( user.email ) {
        userent.load$({email:user.email},function(err,userfound){
          if( err ) return done(err,{ok:false,user:user})
          if( userfound ) return done(null,{ok:false,why:'email-exists',nick:args.nick})
          next()
        })
        return
      }
      next()
    }

    function saveuser() {
      seneca.act({ role:role, cmd:'encrypt_password', whence:'register/user='+user.nick,
        password: args.password, repeat: args.repeat },function( err, out ){
        if( err ) return done(err);
        if( !out.ok ) return done(null,out);

        user.salt = out.salt
        user.pass = out.pass
        user.rounds = out.rounds


        user.save$( function( err, user ){
          if( err ) return done(err)

          seneca.log.debug('register',user.nick,user.email,user)
          done(null,{ok:true,user:user})
        })
      })
    }
  }


  // Action Implementations
  ;


  function resolve_user( cmd, fail ) {
    return function( args, done ) {
      var seneca = this
      var userent  = seneca.make('sys/user')

      if( args.user && args.user.entity$ ) {
        return cmd.call( seneca, args, done )
      }
      else {
        var q = {}, valid = false


        if( args.email && args.nick ) {

          // email wins
          if( args.email !== args.nick ) {
            q.email = args.email
            valid = true
          }
          else if( ~args.email.indexOf('@') ) {
            q.email = args.email
            valid = true
          }
          else {
            q.nick = args.nick
            valid = true
          }
        }
        else if( args.email ) {
          q.email = args.email
          valid = true
        }
        else if( args.nick ) {
          q.nick = args.nick
          valid = true
        }
        else if( args.username ) {
          q.nick = args.username
          valid = true
        }
        else if( args.user && !args.user.entity$) {
          q.id = args.user
          valid = true
        }

        if( !valid ) {
          return done(null,{ok:false,why:'nick_or_email_missing'})
        }

        userent.load$(q, function( err, user ){
          if( err ) return done(err);
          if( !user ) {
            if( fail ) {
              return seneca.fail({code:'user/not-found',q:q});
            }
            else return done(null,{ok:false,why:'user-not-found',nick:q.nick,email:q.email})
          }
          args.user = user

          return cmd.call( seneca, args, done )
        })
      }
    }
  }


  return {
    name:role
  }
}
