import aputils
import asyncio
import logging
import subprocess
import traceback

from pathlib import Path

from . import __version__, misc
from .misc import DotDict, Message, Response
from .processors import run_processor


routes = []
version = __version__


if Path(__file__).parent.parent.joinpath('.git').exists():
	try:
		commit_label = subprocess.check_output(["git", "rev-parse", "HEAD"]).strip().decode('ascii')
		version = f'{__version__} {commit_label}'

	except:
		pass


def register_route(method, path):
	def wrapper(func):
		routes.append([method, path, func])
		return func

	return wrapper


@register_route('GET', '/')
async def home(request):
	targets = '<div class="p-3 border-2 border-slate-300 dark:border-slate-500 border-solid rounded w-full"><h4 class="text-xl">'.join(request.database.hostnames).join('</h4></div>')
	note = request.config.note
	count = len(request.database.hostnames)
	host = request.config.host

	text = f"""
<!doctype html>
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Relay</title>
<link rel="stylesheet" href="/assets/css.css">
<link rel="shortcut icon" href="/assets/i.svg" type="image/svg+xml">
</head>
<body class="text-zinc-700 dark:text-white dark:bg-gray-700">
<div class="overflow-y-auto nz_mobile_bag">
<div class="nz_contents">
<div class="grid gap-4 py-3 lg:py-5 lg:grid-cols-12">
<nav class="lg:col-start-1 lg:col-end-3 lg:column-start-1">
<div class="flex sticky inset-0 w-full h-full max-h-screen">
<div class="relative grid gap-3 w-full h-max">
<div class="grid gap-3 text-white">
<div class="lg:block hidden p-2 lg:border-2 border-slate-300 dark:border-slate-500 lg:border-solid rounded">
<a href="/"><img src="/assets/i.svg" alt="" class="w-full"></a>
</div>
<ul class="lg:grid md:flex grid gap-3 w-full justify-self-center">
<li class="p-2 bg-red-400 dark:bg-gray-800 rounded">
<a href="//about.nauzo.me/about"><div class="flex justify-self-center gap-2">
<span>about</span>
</div>
</li>
<li class="p-2 bg-red-400 dark:bg-gray-800 rounded">
<a href="//blog.nauzome.com"><div class="flex justify-self-center gap-2">
<span>blog</span>
</div>
</li>
</ul>
</div>
</div>
</div>
</nav>
<div class="lg:col-start-3 lg:col-end-13 lg:column-start-1">
<div class="grid gap-5 py-5 px-4 border-2 border-slate-300 dark:border-slate-500 border-solid rounded w-full">
<h1 class="text-3xl">Relay</h1>
<div class="p-2 bg-red-400 dark:bg-gray-800 text-white rounded">
<p>すごい、ベーター版です。</p>
</div>
<div class="grid gap-2">
<h3 class="text-xl">説明</h3>
<p>また、利用規約に従うことにより誰でも接続することができ、自動で承認されます。</p>
</div>
<div class="grid gap-2">
<h3 class="text-xl">利用規約</h3>
<p>管理者は以下の投稿を適切にモデレートする必要があります。</p>
<p>適切にとは24時間以内に削除対応が行えていることです。</p>
<ul class="list-disc list-inside">
<li>合意されていない裸体、性的な画像</li>
<li>児童ポルノ、児童の以下の場合を除く裸体</li>
<ul class="list-disc list-inside">
<li>歴史的に必要な物</li>
<li>教育的に必要な物</li>
</ul>
</ul>
<ul class="list-disc list-inside">
<li>動物虐待的を含む画像、動画それ以上ではない</li>
<li>合意されていない個人情報</li>
<li>未成年者の性行為の呼びかけ若しくは未成年との性行為を促す目的とする投稿</li>
<li>暴力、攻撃の呼びかけ、なお以下は例外</li>
<ul class="list-disc list-inside">
<li>友人同士の悪ふざけ</li>
<li>具体的ではなく実現性が低い投稿</li>
</ul>
</ul>
<p>なお、適切に対応しているのに接続できない場合は<a href="mailto:nauzome@nauzome.com" class="text-blue-700 dark:text-blue-400">nauzome@nauzome.com</a>に連絡してください。</p>
</div>
<div class="grid gap-2">
<h3 class="text-xl">追加方法</h3>
<p>以下のURlを追加してください。</p>
<table class="border-collapse table-auto w-full text-sm">
<tbody>
<tr>
<td class="border border-slate-300 dark:border-slate-500 p-2">mastodon misskey</td>
<td class="border border-slate-300 dark:border-slate-500 p-2"><a href="https://{host}/inbox" class="text-blue-700 dark:text-blue-400">https://{host}/inbox</a></td>
</tr>
<tr>
<td class="border border-slate-300 dark:border-slate-500 p-2">その他</td>
<td class="border border-slate-300 dark:border-slate-500 p-2"><a href="https://{host}/actor" class="text-blue-700 dark:text-blue-400">https://{host}/actor</a></td>
</tr>
</tbody>
</table>
</div>
<div class="grid gap-2">
<h3 class="text-xl">接続情報</h3>
<p>現在{count}のインスタンスが接続されています。</p>
{targets}
</div>
<p>なお、このリレーはpleroma relayを改造した物であり、ライセンスに従いGithubで公開されています。</p>
</div>
</div>
<header class="grid gap-2 lg:column-start-2 lg:col-start-1 lg:col-end-13 py-5 px-3 text-white bg-red-400 dark:bg-gray-800 rounded">
<p>2023-</p>
<p>
<a href="https://github.com/nauzome/relay">ソースコード</a>
</p>
</header>
</div>
</div>
</div>
</body>
</html>
"""

	return Response.new(text, ctype='html')


@register_route('GET', '/inbox')
@register_route('GET', '/actor')
async def actor(request):
	data = Message.new_actor(
		host = request.config.host, 
		pubkey = request.database.signer.pubkey
	)

	return Response.new(data, ctype='activity')


@register_route('POST', '/inbox')
@register_route('POST', '/actor')
async def inbox(request):
	config = request.config
	database = request.database

	## reject if missing signature header
	if not request.signature:
		logging.verbose('Actor missing signature header')
		raise HTTPUnauthorized(body='missing signature')

	try:
		request['message'] = await request.json(loads=Message.new_from_json)

		## reject if there is no message
		if not request.message:
			logging.verbose('empty message')
			return Response.new_error(400, 'missing message', 'json')

		## reject if there is no actor in the message
		if 'actor' not in request.message:
			logging.verbose('actor not in message')
			return Response.new_error(400, 'no actor in message', 'json')

	except:
		## this code should hopefully never get called
		traceback.print_exc()
		logging.verbose('Failed to parse inbox message')
		return Response.new_error(400, 'failed to parse message', 'json')

	request['actor'] = await request.app.client.get(request.signature.keyid, sign_headers=True)

	## reject if actor is empty
	if not request.actor:
		## ld signatures aren't handled atm, so just ignore it
		if request['message'].type == 'Delete':
			logging.verbose(f'Instance sent a delete which cannot be handled')
			return Response.new(status=202)

		logging.verbose(f'Failed to fetch actor: {request.signature.keyid}')
		return Response.new_error(400, 'failed to fetch actor', 'json')

	request['instance'] = request.database.get_inbox(request['actor'].inbox)

	## reject if the actor isn't whitelisted while the whiltelist is enabled
	if config.whitelist_enabled and not config.is_whitelisted(request.actor.domain):
		logging.verbose(f'Rejected actor for not being in the whitelist: {request.actor.id}')
		return Response.new_error(403, 'access denied', 'json')

	## reject if actor is banned
	if request.config.is_banned(request.actor.domain):
		logging.verbose(f'Ignored request from banned actor: {actor.id}')
		return Response.new_error(403, 'access denied', 'json')

	## reject if the signature is invalid
	try:
		await request.actor.signer.validate_aiohttp_request(request)

	except aputils.SignatureValidationError as e:
		logging.verbose(f'signature validation failed for: {actor.id}')
		logging.debug(str(e))
		return Response.new_error(401, str(e), 'json')

	## reject if activity type isn't 'Follow' and the actor isn't following
	if request.message.type != 'Follow' and not database.get_inbox(request.actor.domain):
		logging.verbose(f'Rejected actor for trying to post while not following: {request.actor.id}')
		return Response.new_error(401, 'access denied', 'json')

	logging.debug(f">> payload {request.message.to_json(4)}")

	asyncio.ensure_future(run_processor(request))
	return Response.new(status=202)


@register_route('GET', '/.well-known/webfinger')
async def webfinger(request):
	try:
		subject = request.query['resource']

	except KeyError:
		return Response.new_error(400, 'missing \'resource\' query key', 'json')

	if subject != f'acct:relay@{request.config.host}':
		return Response.new_error(404, 'user not found', 'json')

	data = aputils.Webfinger.new(
		handle = 'relay',
		domain = request.config.host,
		actor = request.config.actor
	)

	return Response.new(data, ctype='json')


@register_route('GET', '/nodeinfo/{version:\d.\d\.json}')
async def nodeinfo(request):
	niversion = request.match_info['version'][:3]

	data = dict(
		name = 'activityrelay',
		version = version,
		protocols = ['activitypub'],
		open_regs = not request.config.whitelist_enabled,
		users = 1,
		metadata = {'peers': request.database.hostnames}
	)

	if niversion == '1.1':
		data['repo'] = 'https://github.com/nauzome/relay'

	return Response.new(aputils.Nodeinfo.new(**data), ctype='json')


@register_route('GET', '/.well-known/nodeinfo')
async def nodeinfo_wellknown(request):
	data = aputils.WellKnownNodeinfo.new_template(request.config.host)
	return Response.new(data, ctype='json')
