// Independent, pinned Adblock Plus core oracle. Reads JSON from stdin only.
const fs = require('fs')
const path = require('path')
const root = path.resolve(__dirname, '../.reference/abp')
const {Filter, BlockingFilter, AllowingFilter, InvalidFilter} = require(root + '/lib/filterClasses')
const {Matcher} = require(root + '/lib/matcher')
const {contentTypes} = require(root + '/lib/contentTypes')
const {URLRequest, parseURL} = require(root + '/lib/url')
const input = JSON.parse(fs.readFileSync(0, 'utf8'))
const blocking = new Matcher()
const allowing = new Matcher()
const diagnostics = []
for (const text of input.rules) {
  const filter = Filter.fromText(Filter.normalize(text))
  if (filter instanceof InvalidFilter) diagnostics.push({text, reason: filter.reason})
  else if (filter instanceof BlockingFilter) blocking.add(filter)
  else if (filter instanceof AllowingFilter) allowing.add(filter)
}
const outputs = input.requests.map(request => {
  const domain = parseURL(request.document_url).hostname.replace(/\.$/, '')
  const type = contentTypes[request.resource_type.toUpperCase()]
  if (!type) throw new Error('unknown reference resource type')
  const chain = [request.document_url, ...(request.ancestors || [])]
  let documentAllowed = false
  let genericDisabled = false
  for (let i = 0; i < chain.length; i++) {
    const parent = parseURL(chain[i + 1] || chain[i]).hostname.replace(/\.$/, '')
    documentAllowed ||= !!allowing.matchesAny(chain[i], contentTypes.DOCUMENT, parent, null, false)
    genericDisabled ||= !!allowing.matchesAny(chain[i], contentTypes.GENERICBLOCK, parent, null, false)
  }
  const allow = documentAllowed || allowing.matchesAny(request.url, type, domain, null, false)
  const block = blocking.matchesAny(request.url, type, domain, null, genericDisabled)
  return {decision: allow ? 2 : block ? 1 : 0,
          third_party: URLRequest.from(request.url, domain).thirdParty}
})
process.stdout.write(JSON.stringify({diagnostics, outputs}))
