const Koa = require('koa')
const BodyParser = require('koa-bodyparser')
const Router = require('koa-router')

const zxcvbn = require('zxcvbn')
const { pwnedPassword } = require('hibp')

const PORT = process.env.PORT || 3000
const MIN_SCORE = process.env.MIN_SCORE || 3

var app = new Koa()
var router = new Router()

var passwordCheck = async function (ctx) {
  const body = ctx.request.body

  if (!body.password) ctx.throw(400, 'password required')

  ctx.body = {}

  if (zxcvbn(body.password).score < MIN_SCORE) {
    ctx.body = { valid: false }
    return
  }

  await pwnedPassword(body.password)
    .then(numPwns => {
      if (numPwns) {
        ctx.body = { valid: false }
      } else {
        ctx.body = { valid: true }
      }
    })
    .catch(_ => {
      ctx.status = 500
      ctx.body = { valid: null }
    })
}

router
  .post('/password-check', passwordCheck)

app
  .use(BodyParser())
  .use(router.routes())
  .use(router.allowedMethods())

app.listen(PORT)
