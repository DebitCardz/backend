import express from 'express'

import { authMiddleware, userIsAdmin } from '../util/Middleware'
import { Invite, InviteType } from '../database/entities/Invite'
import { randomBytes } from '../util/RandomUtil'
import { User } from '../database/entities/User'
import argon2, { argon2id } from 'argon2'
import bodyParser from 'body-parser'
import { Image } from '../database/entities/Image'
import { storage } from '../util/StorageUtil'
import { Testimonial } from '../database/entities/Testimonial'
import filter from '../util/FilterUtil'
import { ShortURL } from '../database/entities/ShortURL'
import { sendMail, verifyEmailTemplate } from '../util/MailUtil'

const valid_username_regex = /^[a-z0-9]+$/i
const email_regex = /(?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])/

const UsersRouter = express.Router()

UsersRouter.use(bodyParser.json())

UsersRouter.use(authMiddleware())

UsersRouter.route('/').get(userIsAdmin(), async (req, res) => {
  let limit = 50
  let page = 0
  if (req.query && req.query.limit) {
    limit = parseInt(req.query.limit as string)
  }
  if (req.query && req.query.page) {
    page = parseInt(req.query.page as string)
  }
  page = page * limit
  let users = await User.find({
    order: {
      id: 'ASC',
    },
    take: limit,
    skip: page,
  })
  let count = await User.count()
  return res.status(200).json({
    success: true,
    message: 'users',
    users: users.map((user) => user.serialize()),
    total: count,
    page: page,
    pages: Math.ceil(count / limit) - 1,
  })
})

const userWhitelist = [
  'settings_discordLink',
  'settings_apiIpSecurity',
  'settings_randomDomains',
  'settings_secureURLs',
  'settings_invisibleShortURLs',
  'settings_ipSecurity',
] //TODO: look into just .startsWith('settings_') instead of a whitelist

const betaWhitelist = ['settings_imageMiddleware']

async function getUser(
  req: express.Request,
  moderator: boolean = false
): Promise<User> {
  let user = req.user
  if (
    req.params.id !== '@me' &&
    (req.user.admin || (moderator && req.user.moderator))
  ) {
    user = (await User.findOne({
      where: {
        id: req.params.id,
      },
    })) as User
    if (!user) throw new Error('User does not exist')
  }
  return user
}

UsersRouter.route('/find').get(userIsAdmin(), async (req, res) => {
  let user = await User.findOne({ where: req.body })
  return res.status(200).json({ success: true, user })
})

async function sendVerificationEmail(user: User) {
  return sendMail(
    user.email,
    '[pxl.blue] verify your email',
    verifyEmailTemplate(
      user.username,
      `https://api.pxl.blue/auth/verify_email?k=${user.emailVerificationToken}`
    )
  )
}

UsersRouter.route('/:id')
  .get(async (req, res) => {
    if (req.user.banned) {
      return res.status(401).json({
        success: false,
        errors: [`your account is banned:\n${req.user.banReason}`],
      })
    }
    let user = await getUser(req)
    res.status(200).json({
      success: true,
      message: 'ok',
      user: user.serialize(),
    })
  })
  .patch(async (req, res) => {
    if (!req.body)
      return res.status(400).json({ success: false, errors: ['no body'] })
    let keysModified = []
    Object.keys(req.body).forEach((key) => {
      if (!userWhitelist.includes(key) && !betaWhitelist.includes(key)) return
      if (betaWhitelist.includes(key) && !req.user.betaTester) return
      ;(req.user as any)[key] = req.body[key]
      keysModified.push(key)
    })

    let validPassword = false
    if (req.body.password) {
      validPassword = await argon2.verify(
        req.user.password,
        req.body.password,
        {
          type: argon2id,
        }
      )
    }

    if (req.body.email && typeof req.body.email === 'string') {
      if (!validPassword) {
        return res.status(401).json({
          success: false,
          errors: ['existing password is not correct'],
        })
      }
      req.user.email = req.body.email
      req.user.emailVerified = false
      req.user.lowercaseEmail = req.user.email.toLowerCase()
      req.user.emailVerificationToken = randomBytes()
      await sendVerificationEmail(req.user)
      await req.user.save()
      return res.status(200).json({
        success: true,
        message: 'Please check your new email before logging in again.',
      })
    }

    if (req.body.newPassword && typeof req.body.newPassword === 'string') {
      if (!validPassword) {
        return res.status(401).json({
          success: false,
          errors: ['existing password is not correct'],
        })
      }
      let hash = await argon2.hash(req.body.newPassword, {
        type: argon2id,
      })
      req.user.password = hash
      await req.user.save()
      return res
        .status(200)
        .json({ success: true, message: 'Updated your password' })
    }
    await req.user.save()
    return res.status(200).json({ success: true, message: 'modified settings' })
  })
UsersRouter.route('/:id/invites')
  .get(async (req, res) => {
    let user = await getUser(req)
    let invites = await Invite.find({
      where: {
        creator: user.id,
      },
      order: {
        id: 'ASC',
      },
    })
    return res.status(200).json({
      success: true,
      message: 'ok',
      invites: invites.map((invite) => invite.serialize()),
      canCreateInvites: user.admin || user.moderator,
    })
  })
  .post(async (req, res) => {
    let canCreateInvite = req.user.admin || req.user.moderator
    if (!canCreateInvite) {
      return res.status(400).json({
        success: false,
        message: 'cant create invite',
        errors: ['you do not have permission to create a new invite'],
      })
    }

    let invite = new Invite()
    invite.invite = randomBytes(20)
    invite.createdAt = new Date()
    invite.creator = req.user.id
    await invite.save()

    // decrease available invite counter

    return res.status(200).json({
      success: true,
      message: 'invite created',
      invite: invite.serialize(),
    })
  })

UsersRouter.route('/:id/embed')
  .get(async (req, res) => {
    let user = await getUser(req)
    return res.status(200).json({
      success: true,
      settings: {
        embed: user.embed,
        author: user.embedAuthor,
        authorStr: user.embedAuthorStr,
        title: user.embedTitle,
        description: user.embedDescription,
        color: user.embedColor,
      },
    })
  })
  .post(async (req, res) => {
    let user = await getUser(req)

    if (typeof req.body.embed === 'boolean') user.embed = req.body.embed
    if (typeof req.body.author === 'boolean') user.embedAuthor = req.body.author
    if (typeof req.body.title === 'string') user.embedTitle = req.body.title
    if (typeof req.body.description === 'string')
      user.embedDescription = req.body.description
    if (typeof req.body.authorStr === 'string')
      user.embedAuthorStr = req.body.authorStr
    if (typeof req.body.color === 'string') {
      if (!req.body.color.match(/#[0-9a-f]{6}/gi))
        return res.status(400).json({
          success: false,
          errors: ['"color" is not a hex color (e.g. #ff00ff)'],
        })
      user.embedColor = req.body.color
    }

    await user.save()
    return res.status(200).json({
      success: true,
      settings: {
        embed: user.embed,
        author: user.embedAuthor,
        authorStr: user.embedAuthorStr,
        title: user.embedTitle,
        description: user.embedDescription,
        color: user.embedColor,
      },
    })
  })

UsersRouter.route('/:id/middleware')
  .get(async (req, res) => {
    let user = await getUser(req)

    return res
      .status(200)
      .json({ success: true, middleware: user.imageMiddleware })
  })
  .patch(async (req, res) => {
    let user = await getUser(req)

    // validate this against a schema at some point
    user.imageMiddleware = req.body
    await user.save()

    return res
      .status(200)
      .json({ success: true, middleware: user.imageMiddleware })
  })

UsersRouter.route('/:id/images').get(async (req, res) => {
  let user = await getUser(req)
  let limit = 50
  let page = 0
  let order: 'ASC' | 'DESC' = 'ASC'
  if (req.query && req.query.limit) {
    limit = parseInt(req.query.limit as string)
  }
  if (req.query && req.query.page) {
    page = parseInt(req.query.page as string)
  }
  if (req.query && req.query.order === 'DESC') order = 'DESC'
  page = page * limit
  let images = await Image.find({
    order: {
      id: order,
    },
    where: {
      uploader: user.id,
      deleted: false,
    },
    take: limit,
    skip: page,
  })
  let count = await Image.count({
    where: {
      uploader: user.id,
      deleted: false,
    },
  })
  return res.status(200).json({
    success: true,
    message: 'images',
    images: images.map((image) => image.serialize()),
    total: count,
    page: page,
    pages: Math.ceil(count / limit) - 1,
  })
})

UsersRouter.route('/:id/images/nuke').post(async (req, res) => {
  let user = await getUser(req)
  let images = await Image.find({
    where: {
      uploader: user.id,
      deleted: false,
    },
  })
  // TODO: batch delete
  Promise.all(
    images.map(async (image) => {
      return new Promise((resolve, reject) => {
        storage.removeObject(
          process.env.STORAGE_BUCKET!,
          image.path,
          async () => {
            image.deleted = true
            image.deletionReason = 'USER'
            await image.save()
            resolve()
          }
        )
      })
    })
  ).then(async () => {
    user.imageCount = await Image.count({
      where: {
        uploader: user.id,
        deleted: false,
      },
    })
    await user.save()
  })
  return res.status(200).json({
    success: true,
    message: 'your images have been queued for deletion',
  })
})

UsersRouter.route('/:id/shorturls').get(async (req, res) => {
  let user = await getUser(req)
  let limit = 50
  let page = 0
  let order: 'ASC' | 'DESC' = 'ASC'
  if (req.query && req.query.limit) {
    limit = parseInt(req.query.limit as string)
  }
  if (req.query && req.query.page) {
    page = parseInt(req.query.page as string)
  }
  if (req.query && req.query.order === 'DESC') order = 'DESC'
  page = page * limit
  let urls = await ShortURL.find({
    order: {
      id: order,
    },
    where: {
      creator: user.id,
    },
    take: limit,
    skip: page,
  })
  let count = await ShortURL.count({
    where: {
      creator: user.id,
    },
  })
  return res.status(200).json({
    success: true,
    message: 'urls',
    urls: urls.map((url) => url.serialize()),
    total: count,
    page: page,
    pages: Math.ceil(count / limit) - 1,
  })
})

UsersRouter.route('/:id/shorturls/nuke').post(async (req, res) => {
  let user = await getUser(req)

  await ShortURL.getRepository()
    .createQueryBuilder()
    .delete()
    .from(ShortURL)
    .where('creator = :id', { id: user.id })
    .execute()

  return res.status(200).json({
    success: true,
    message: 'your shorturls have been deleted',
  })
})

UsersRouter.route('/:id/keys/:key/regenerate').post(async (req, res) => {
  let user = await getUser(req)

  if (!['uploadKey', 'apiKey'].includes(req.params.key))
    return res.status(400).json({
      success: false,
      errors: [`you cannot regenerate key of type "${req.params.key}"`],
    })
  let key = randomBytes()
  user[req.params.key as 'uploadKey' | 'apiKey'] = key //TODO: typescript is kind of annoying, and i should likely find a better way to do this
  await user.save()
  return res.status(200).json({
    success: true,
    message: `successfully regenerated key of type "${req.params.key}"`,
    newValue: key,
  })
})

UsersRouter.route('/:id/testimonial')
  .get(async (req, res) => {
    let user = await getUser(req)

    let testimonial = await Testimonial.findOne({
      where: { author: user.id },
    })
    if (!testimonial)
      return res
        .status(400)
        .json({ success: false, errors: ['testimonial not created'] })
    return res.status(200).json({
      success: true,
      testimonial: testimonial.serialize(),
    })
  })
  .post(async (req, res) => {
    let user = await getUser(req)

    let testimonial = await Testimonial.findOne({
      where: { author: user.id },
    })

    if (filter.isProfane(req.body.testimonial)) {
      return res.status(400).json({
        success: false,
        errors: [
          'your testimonial contains a bad word',
          `hint (cleaned version): ${filter.clean(req.body.testimonial)}`,
        ],
      })
    }
    if (!testimonial) {
      testimonial = new Testimonial()
      testimonial.author = user.id
      testimonial.testimonial = req.body.testimonial.substr(0, 100)
      testimonial.createdAt = new Date()
      await testimonial.save()
      return res.json({
        success: true,
        message: 'Updated testimonial successfully',
        testimonial: testimonial.serialize(),
      })
    }
    testimonial.testimonial = req.body.testimonial.substr(0, 100)
    await testimonial.save()
    return res.json({
      success: true,
      message: 'Updated testimonial successfully',
      testimonial: testimonial.serialize(),
    })
  })

UsersRouter.route('/:id/unlimit').post(async (req, res) => {
  let user = await getUser(req)

  if (!user.limited)
    return res
      .status(400)
      .json({ success: false, errors: ['your account is not limited'] })

  let invite = await Invite.findOne({
    where: {
      invite: req.body.invite,
      redeemed: false,
      type: InviteType.DEFAULT,
    },
  })
  if (!invite)
    return res.status(400).json({
      success: false,
      errors: ['invite does not exist, or was already redeemed.'],
    })
  invite.redeemed = true
  invite.redeemedAt = new Date()
  invite.redeemedBy = user.id
  invite.redeemedByUsername = user.username
  await invite.save()

  user.limited = false
  await user.save()

  return res
    .status(200)
    .json({ success: true, message: 'your account is now unlimited!' })
})

const BASE_UPLOADER_CONFIG = {
  Version: '13.1.0',
  Name: 'pxl.blue (%username%)',
  DestinationType: 'ImageUploader, FileUploader',
  RequestMethod: 'POST',
  RequestURL: 'https://api.pxl.blue/upload/extra',
  Body: 'MultipartFormData',
  Arguments: {
    key: '%key%',
    host: 'i.pxl.blue',
  },
  FileFormName: 'file',
  URL: '$json:url$',
  DeletionURL: '$json:deletionUrl$',
}

const BASE_SHORTENER_CONFIG = {
  Version: '13.1.0',
  Name: 'pxl.blue URL shortener (%username%)',
  DestinationType: 'URLShortener',
  RequestMethod: 'POST',
  RequestURL: 'https://api.pxl.blue/upload/shorten',
  Body: 'FormURLEncoded',
  Arguments: {
    key: '%key%',
    host: 'i.pxl.blue',
    destination: '$input$',
  },
  URL: '$json:url$',
}

UsersRouter.route('/@me/generate_sharex_config').get(async (req, res) => {
  let cfg = {
    ...BASE_UPLOADER_CONFIG,
    Name: `pxl.blue (${req.user.username} on ${
      req.query.domain || 'i.pxl.blue'
    })`,
    Arguments: {
      key: req.user.uploadKey,
      host: req.query.domain || 'i.pxl.blue',
    },
  }
  res.setHeader(
    'Content-Disposition',
    `attachment; filename=pxl.blue_${req.user.username}_on_${cfg.Arguments.host}.sxcu`
  )
  res.setHeader('Content-Transfer-Encoding', 'binary')
  res.setHeader('Content-Type', 'application/octet-stream')
  return res.send(JSON.stringify(cfg))
})

UsersRouter.route('/@me/generate_shortener_config').get(async (req, res) => {
  let cfg = {
    ...BASE_SHORTENER_CONFIG,
    Name: `pxl.blue URL shortener (${req.user.username} on ${
      req.query.domain || 'i.pxl.blue'
    })`,
    Arguments: {
      key: req.user.uploadKey,
      host: req.query.domain || 'i.pxl.blue',
      destination: '$input$',
    },
  }
  res.setHeader(
    'Content-Disposition',
    `attachment; filename=pxl.blue_urlshortener_${req.user.username}_on_${cfg.Arguments.host}.sxcu`
  )
  res.setHeader('Content-Transfer-Encoding', 'binary')
  res.setHeader('Content-Type', 'application/octet-stream')
  return res.send(JSON.stringify(cfg))
})

// admin routes
UsersRouter.route('/:id/suspend').post(userIsAdmin(), async (req, res) => {
  let user = await getUser(req)
  user.banned = true
  user.banReason = req.body.reason
  await user.save()

  return res.status(200).json({ success: true, user: user.serialize() })
})
UsersRouter.route('/:id/unsuspend').post(userIsAdmin(), async (req, res) => {
  let user = await getUser(req)
  user.banned = false
  await user.save()

  return res.status(200).json({ success: true, user: user.serialize() })
})

export default UsersRouter
