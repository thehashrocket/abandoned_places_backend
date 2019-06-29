const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomBytes } = require('crypto');
const { promisify } = require('util');
const { transport, makeANiceEmail } = require('../mail');
const { hasPermission } = require('../utils');

const mutations = {
  async createLocation(parent, args, ctx, info) {
    // TODO: Check if they are logged in
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do that!')
    }

    const location = await ctx.db.mutation.createLocation({
      data: {
        // This is how to create a relationship between the Location and the user.
        user: {
          connect: {
            id: ctx.request.userId,
          }
        },
        ...args,
      }
    }, info)

    return location;

  },
  updateLocation(parent, args, ctx, info) {
    // first take a copy of the updates
    const updates = { ...args };
    // remove the ID from the updates
    delete updates.id;
    // run the update method
    return ctx.db.mutation.updateLocation({
      data: updates,
      where: {
        id: args.id
      }
    }, info)
  },

  async deleteLocation(parent, args, ctx, info) {
    const where = { id: args.id };
    // find the location
    const location = await ctx.db.query.location({ where }, `{id title user { id }}`);
    // check if they own that location or have the permissions
    const ownsLocation = location.user.id === ctx.request.userId;
    const hasPermissions = ctx.request.user.permissions.some(
      permissions => ['ADMIN', 'LOCATIONDELETE'].includes(permissions)
    );
    if (!ownsLocation || !hasPermissions) {
      throw new Error("You don't have permissions to do that!")
    }
    // Delete it!
    return ctx.db.mutation.deleteLocation({ where }, info);
  },
  async signup(parent, args, ctx, info) {
    // lowercase their email
    args.email = args.email.toLowerCase();
    // hash their password
    const password = await bcrypt.hash(args.password, 10);
    // create the user in the database
    const user = await ctx.db.mutation.createUser({
      data: {
        ...args,
        password,
        permissions: { set: ['USER'] }
      }
    }, info);
    // create the JWT token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // we set the jwt as a cookie on the response
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year cookie
    });
    // Return user to the browser
    return user;
  },

  async signup(parent, args, ctx, info) {
    // lowercase their email
    args.email = args.email.toLowerCase();
    // hash their password
    const password = await bcrypt.hash(args.password, 10);
    // create the user in the database
    const user = await ctx.db.mutation.createUser({
      data: {
        ...args,
        password,
        permissions: { set: ['USER'] }
      }
    }, info);
    // create the JWT token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // we set the jwt as a cookie on the response
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year cookie
    });
    // Return user to the browser
    return user;
  },
  async signin(parent, { email, password }, ctx, info) {
    // check if the there is a user with that email.
    email = email.toLowerCase();
    const user = await ctx.db.query.user({ where: { email: email } });
    if (!user) {
      throw new Error(`No such user for email ${email}`);
    }
    // check if there password is correct
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) {
      throw new Error('Invalid password!');
    }
    // generate the JWT Token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET);
    // Set the cookie
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year cookie
    });
    // Return user to the browser
    return user;
  },
  async signout(parent, args, ctx, info) {
    ctx.response.clearCookie('token');
    return { message: 'Goodbye!' };
  },
  async requestReset(parent, args, ctx, info) {
    // check if this is a real user
    const user = await ctx.db.query.user({ where: { email: args.email } })
    if (!user) {
      throw new Error(`No such user for email ${args.email}`);
    }
    // set a reset token and expiry on that user
    const randomBytesPromisified = promisify(randomBytes);
    const resetToken = (await randomBytesPromisified(20)).toString('hex');
    const resetTokenExpiry = Date.now() + 3600000; // 1 hour from now.
    const res = await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry },
    });

    // email user a reset token
    const mailRes = await transport.sendMail({
      from: 'some@guy.com',
      to: user.email,
      subject: 'Your password reset token',
      html: makeANiceEmail(`Your password reset Token is here:
      \n\n
      <a href = "${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">Click Here to Reset</a>`)
    })
    // Return the message
    return { message: 'Thanks!' }
  },
  async resetPassword(parent, args, ctx, info) {
    // check if the password match
    if (args.password !== args.confirmPassword) {
      throw new Error('Your password do not match!');
    }
    // check if its a legit reset token
    // check if it's expired
    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 3600000
      }
    })
    if (!user) {
      throw new Error('This token is either invalid or expired');
    }
    // hash their new password
    const password = await bcrypt.hash(args.password, 10);
    // save the new password to the user and remove old resetToken fields.
    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: {
        password,
        resetToken: null,
        resetTokenExpiry: null,
      }
    })
    // Generate JWT
    const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET);
    // Set the JWT cookie
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365, // 1 year cookie
    });
    // return the new user
    return updatedUser;
  },
  async updatePermissions(parent, args, ctx, info) {
    // 1. check if they are logged in.
    if (!ctx.request.userId) {
      throw new Error('You must be logged in!');
    }
    // 2. query the current user
    const currentUser = await ctx.db.query.user({
      where: {
        id: ctx.request.userId
      }
    }, info
    );
    // 3. check if they have permissions.
    hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE']);
    // 4. update the permissions
    return ctx.db.mutation.updateUser({
      data: {
        permissions: {
          set: args.permissions
        }
      },
      where: {id: args.userId}
    }, info);
  }
};

module.exports = mutations;
