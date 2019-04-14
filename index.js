const Koa = require('koa')
const BodyParser = require('koa-bodyparser')
const Router = require('koa-router')
const zxcvbn = require('zxcvbn')
const { pwnedPassword } = require('hibp')

var app = new Koa()
var router = new Router()

var passwordCheck = async function (ctx) {
  const body = ctx.request.body

  if (!body.password) ctx.throw(400, 'password required')

  if (await pwnedPassword(body.password)) {
    ctx.body = { score: -1 }
  } else {
    const result = zxcvbn(body.password)

    ctx.body = { score: result.score }
  }
}

router
  .post('/password', passwordCheck)

app
  .use(BodyParser())
  .use(router.routes())
  .use(router.allowedMethods())

app.listen(3000)
