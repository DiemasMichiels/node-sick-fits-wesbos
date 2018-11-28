const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const { randomBytes } = require('crypto')
const { promisify } = require('util')
const { transport, makeANiceEmail } = require('../mail')
const { hasPermission } = require('../utils')

const Mutations = {
  async createItem (parent, args, ctx, info) {
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do that!')
    }

    const item = await ctx.db.mutation.createItem({
      data: {
        // This is how we create a relationship between the item and a user
        user: {
          connect: {
            id: ctx.request.userId
          }
        },
        ...args
      }
    }, info)

    return item
  },
  updateItem (parent, args, ctx, info) {
    // first take a copy of the updates
    const updates = { ...args }
    // remove the ID from the updates
    delete updates.id
    // run the update method
    return ctx.db.mutation.updateItem({
      data: updates,
      where: {
        id: args.id
      }
    }, info)
  },
  async deleteItem (parent, args, ctx, info) {
    const where = { id: args.id }
    // 1. find the item
    const item = await ctx.db.query.item({ where }, `{ id title user { id } }`)
    // 2. check if they own that item, or have the permissions
    const ownsItem = item.user.id === ctx.request.userId
    const hasPermissions = ctx.request.user.permissions.some(permission => ['ADMIN', 'ITEMDELETE'].includes(permission))

    if (!ownsItem && hasPermissions) {
      throw new Error('You don\'t have permission to do that!')
    }
    // 3. delete it
    return ctx.db.mutation.deleteItem({ where }, info)
  },
  async signup (parent, args, ctx, info) {
    args.email = args.email.toLowerCase()
    // hash their password
    const password = await bcrypt.hash(args.password, 10)
    const user = await ctx.db.mutation.createUser({
      data: {
        ...args,
        password,
        permissions: { set: ['USER'] }
      }
    }, info)
    // create JWT token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET)
    // set JWT as a cookie on the response
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    })
    // return the user
    return user
  },
  async signin (parent, { email, password }, ctx, info) {
    // check if there is a user with that email
    const user = await ctx.db.query.user({ where: { email } })
    if (!user) {
      throw new Error(`No such user found for email ${email}`)
    }
    // check if the password is correct
    const valid = await bcrypt.compare(password, user.password)
    if (!valid) {
      throw new Error(`Invalid password`)
    }
    // gen jwt token
    const token = jwt.sign({ userId: user.id }, process.env.APP_SECRET)
    // set cookie with jwt
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    })
    // return user
    return user
  },
  signout (parent, args, ctx, info) {
    ctx.response.clearCookie('token')
    return { message: 'Goodbye!' }
  },
  async requestReset (parent, args, ctx, info) {
    // check if this is a real user
    const user = await ctx.db.query.user({ where: { email: args.email } })
    if (!user) {
      throw new Error(`No such user found for email ${args.email}`)
    }
    // set reset token and expiry on that user
    const randomBytesPromisified = promisify(randomBytes)
    const resetToken = (await randomBytesPromisified(20)).toString('hex')
    const resetTokenExpiry = Date.now() + 3600000
    const res = await ctx.db.mutation.updateUser({
      where: { email: args.email },
      data: { resetToken, resetTokenExpiry }
    })
    // email them that rest token
    const mailRes = await transport.sendMail({
      from: 'michielsdiemas@gmail.com',
      to: user.email,
      subject: 'Your password reset token',
      html: makeANiceEmail(`Your password email token is here \n\n <a href="${process.env.FRONTEND_URL}/reset?resetToken=${resetToken}">Click here to reset</a>`)
    })

    // return a message
    return { message: 'Thanks!' }
  },
  async resetPassword (parent, args, ctx, info) {
    // check if the passwords match
    if (args.password !== args.confirmPassword) {
      throw new Error('Your passwords do not match')
    }
    // check if its a legit reset token
    // check if its expired
    const [user] = await ctx.db.query.users({
      where: {
        resetToken: args.resetToken,
        resetTokenExpiry_gte: Date.now() - 3600000
      }
    })
    if (!user) {
      throw new Error('This token is either invalid or expired!')
    }
    // hsh new password
    const password = await bcrypt.hash(args.password, 10)
    // save new password en remove old restToken fields
    const updatedUser = await ctx.db.mutation.updateUser({
      where: { email: user.email },
      data: {
        password,
        resetToken: null,
        resetTokenExpiry: null
      }
    }, info)
    // generate jwt
    const token = jwt.sign({ userId: updatedUser.id }, process.env.APP_SECRET)
    // set jwt cookie
    ctx.response.cookie('token', token, {
      httpOnly: true,
      maxAge: 1000 * 60 * 60 * 24 * 365 // 1 year cookie
    })
    // return user
    return updatedUser
  },
  async updatePermissions (parent, args, ctx, info) {
    // check if they are logged in
    if (!ctx.request.userId) {
      throw new Error('You must be logged in to do that!')
    }
    // query the current user
    const currentUser = await ctx.db.query.user({
      where: { id: ctx.request.userId }
    }, info)
    // check if thet have permissions to do this
    hasPermission(currentUser, ['ADMIN', 'PERMISSIONUPDATE'])
    // update the permissions
    return ctx.db.mutation.updateUser({
      data: {
        permissions: {
          set: args.permissions
        }
      },
      where: {
        id: args.userId
      }
    }, info)
  },
  async addToCart (parent, args, ctx, info) {
    // make sure they are signed in
    const { userId } = ctx.request
    if (!userId) {
      throw new Error('You must be logged in to do that!')
    }
    // query the users current cart
    const [existingCartItem] = await ctx.db.query.cartItems({
      where: {
        user: { id: userId },
        item: { id: args.id }
      }
    })
    // check if the item is already in the cart and increment by 1 if it is
    if (existingCartItem) {
      return ctx.db.mutation.updateCartItem({
        where: { id: existingCartItem.id },
        data: { quantity: existingCartItem.quantity + 1 }
      }, info)
    }
    // if its not ,create a fresh
    return ctx.db.mutation.createCartItem({
      data: {
        user: {
          connect: { id: userId }
        },
        item: {
          connect: { id: args.id }
        }
      }
    }, info)
  },
  async removeFromCart (parent, args, ctx, info) {
    // find the cart item
    const cartItem = await ctx.db.query.cartItem({
      where: {
        id: args.id
      }
    }, `{ id, user { id }}`)
    // make sure we found an item
    if (!cartItem) throw new Error('No CartItem Found!')
    // make sure they own that cart item
    if (cartItem.user.id !== ctx.request.userId) {
      throw new Error('Cheating??? :O')
    }
    // delete that cart item
    return ctx.db.mutation.deleteCartItem({
      where: {
        id: args.id
      }
    }, info)
  }
}

module.exports = Mutations
