const { forwardTo } = require('prisma-binding');
const { hasPermission } = require('../utils');
const Query = {
  // async items(parent, args, ctx, info) {
  //   const items = await ctx.db.query.items();
  //   return items;
  // }
  locations: forwardTo('db'),
  location: forwardTo('db'),
  locationsConnection: forwardTo('db'),

  me(parent, args, ctx, info) {
    // check if there is a current user ID
    if (!ctx.request.userId) {
      return null;
    }
    return ctx.db.query.user({
      where: { id: ctx.request.userId },
    }, info);
  },

  async users(parent, args, ctx, info) {
    // check if they are logged in
    if (!ctx.request.userId) {
      throw new Error('You must be logged in!');
    }
    // 1. Check if the user has the permissions to query all the users.
    hasPermission(ctx.request.user, ['ADMIN', 'PERMISSIONUPDATE']);
    // 2. If they do, query all the users!
    return ctx.db.query.users({}, info);
  },

  async hasPermissions(parent, args, ctx, info) {
    // check if they are logged in
    if (!ctx.request.userId) {
      throw new Error('You must be logged in!');
    }

    if (!args['permissions']) {
      throw new Error('No Permissions provided.');
    }
    perms = args['permissions'].split(',');

    const matchedPermissions = ctx.request.user.permissions.filter(permissionTheyHave =>
      perms.includes(permissionTheyHave)
    );

    if (!matchedPermissions.length) {
      return false;
    } else {
      return ctx.request.user
    }
  }

};

module.exports = Query;
