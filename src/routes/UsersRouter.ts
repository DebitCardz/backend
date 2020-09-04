import express from 'express'

import { authMiddleware, userIsAdmin } from '../util/Middleware'
import { Invite } from '../database/entities/Invite'
import { randomBytes } from '../util/RandomUtil'
import { User } from '../database/entities/User'
import bodyParser from 'body-parser'
import { Image } from '../database/entities/Image'
import { bucket } from '../util/StorageUtil'

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

UsersRouter.route('/:id').get(async (req, res) => {
  if (req.user.banned) {
    return res.status(401).json({
      success: false,
      errors: [`your account is banned:\n${req.user.banReason}`],
    })
  }
  let user = req.user
  if (req.params.id !== '@me' && req.user.admin) {
    user = (await User.findOne({
      where: {
        id: req.params.id,
      },
    })) as User
    if (!user)
      return res
        .status(400)
        .json({ success: false, errors: ['that user does not exist'] })
  }
  res.status(200).json({
    success: true,
    message: 'ok',
    user: user.serialize(),
  })
})

UsersRouter.route('/:id/invites')
  .get(async (req, res) => {
    let user = req.user
    if (req.params.id !== '@me' && req.user.admin) {
      user = (await User.findOne({
        where: {
          id: req.params.id,
        },
      })) as User
      if (!user)
        return res
          .status(400)
          .json({ success: false, errors: ['that user does not exist'] })
    }
    let invites = await Invite.find({
      where: {
        creator: user.id,
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

UsersRouter.route('/:id/images').get(async (req, res) => {
  let user = req.user
  if (req.params.id !== '@me' && req.user.admin) {
    user = (await User.findOne({
      where: {
        id: req.params.id,
      },
    })) as User
    if (!user)
      return res
        .status(400)
        .json({ success: false, errors: ['that user does not exist'] })
  }
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
  let user = req.user
  if (req.params.id !== '@me' && req.user.admin) {
    user = (await User.findOne({
      where: {
        id: req.params.id,
      },
    })) as User
    if (!user)
      return res
        .status(400)
        .json({ success: false, errors: ['that user does not exist'] })
  }
  let images = await Image.find({
    where: {
      uploader: user.id,
      deleted: false,
    },
  })
  Promise.all(
    images.map(async (image) => {
      await bucket.file(image.path).delete()
      image.deleted = true
      image.deletionReason = 'USER'
      await image.save()
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

const BASE_UPLOADER_CONFIG = {
  Version: '13.1.0',
  Name: 'pxl.blue (%username%)',
  DestinationType: 'ImageUploader, FileUploader',
  RequestMethod: 'POST',
  RequestURL: 'https://api.pxl.blue/upload/sharex',
  Body: 'MultipartFormData',
  Arguments: {
    key: '%key%',
    host: 'i.pxl.blue',
  },
  FileFormName: 'file',
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

export default UsersRouter
