/* Evaluator-owned fixture assertions. Docker only; never a registered Agent tool.
 * Credentials/tokens are ephemeral in-memory and never printed or persisted.
 */
const assert = require('node:assert/strict')
const crypto = require('node:crypto')
const http = require('node:http')
let phase='availability'
const req = (method, path, data, token) => new Promise((resolve, reject) => {
  const body = data === undefined ? '' : JSON.stringify(data)
  const request = http.request({hostname:'127.0.0.1', port:3000, method, path,
    headers:{'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),
      ...(token ? {Authorization:'Bearer '+token,Cookie:'token='+token} : {})}}, response => {
    let text=''; response.on('data', b => {text+=b;if(text.length>262144)request.destroy(new Error('bounded response'))})
    response.on('end',()=>{try{resolve({code:response.statusCode, body:JSON.parse(text)})}catch{reject(new Error('invalid response'))}})
  })
  request.on('error',reject);request.setTimeout(3000,()=>request.destroy(new Error('timeout')))
  request.end(body)
})
const ok = response => {assert.equal(response.code,200);return response.body.data}
const identity = async (user) => {
  const response = await req('GET','/rest/user/whoami',undefined,user.token)
  assert.equal(response.code,200)
  const result = response.body.user
  assert.equal(result.id,user.id);assert.equal(result.email,user.email)
}
;(async()=>{
  const challenges = ok(await req('GET','/api/Challenges'))
  phase='fresh_challenges'
  assert(challenges.length>0)
  assert(challenges.every(x=>x.solved===false),'fresh challenge state required')
  const baseline = crypto.createHash('sha256').update(JSON.stringify(challenges.map(x=>[x.key,x.solved]).sort())).digest('hex')
  // OS CSPRNG is the ephemeral benchmark credential source. No upstream accounts.
  const users=[]
  for(const role of ['owner','other_user']) {
    phase='register_'+role
    const email='cft-a03-'+role+'@example.invalid', password=crypto.randomBytes(32).toString('base64url')
    const created=await req('POST','/api/Users',{email,password,passwordRepeat:password})
    assert.equal(created.code,201)
    phase='login_'+role
    const login=await req('POST','/rest/user/login',{email,password})
    assert.equal(login.code,200)
    const auth=login.body.authentication
    assert(auth.token && Number.isInteger(auth.umail===email ? auth.bid : NaN))
    const user={email,token:auth.token,id:created.body.data.id}
    phase='identity_'+role
    await identity(user)
    assert.deepEqual(ok(await req('GET','/api/Addresss',undefined,user.token)),[])
    assert.deepEqual(ok(await req('GET','/api/Cards',undefined,user.token)),[])
    users.push(user)
  }
  assert.notEqual(users[0].id,users[1].id)
  const owned={}
  for(const user of users) {
    for(const resource of ['Addresss','Cards']) {
      phase='object_create_'+resource
      const data=resource==='Addresss' ? {fullName:'A03 fixture',mobileNum:1234567890,zipCode:'10000',streetAddress:'fixture',city:'fixture',country:'fixture'} :
        {fullName:'A03 fixture',cardNum:1234567890123456,expMonth:12,expYear:2090}
      // Attempted client author forgery must be overwritten by appendUserId.
      data.UserId=users.find(x=>x!==user).id
      const created=await req('POST','/api/'+resource,data,user.token)
      assert.equal(created.code,201);assert.equal(created.body.data.UserId,user.id)
      owned[user.id+resource]=created.body.data.id
    }
  }
  const result={baseline, properties:{}}
  for(const resource of ['Addresss','Cards']) {
    phase='property_'+resource
    for(const owner of users) {
      const other=users.find(x=>x!==owner), id=owned[owner.id+resource]
      const legitimate=ok(await req('GET','/api/'+resource+'/'+id,undefined,owner.token))
      assert.equal(legitimate.id,id);assert.equal(legitimate.UserId,owner.id)
      assert(ok(await req('GET','/api/'+resource,undefined,owner.token)).some(x=>x.id===id))
      const blocked=await req('GET','/api/'+resource+'/'+id,undefined,other.token)
      assert.equal(blocked.code,400);assert.equal(blocked.body.status,'error')
      // A denial is meaningful only with valid identities after the request too.
      await identity(owner);await identity(other)
      assert.equal(ok(await req('GET','/api/'+resource+'/'+id,undefined,owner.token)).id,id)
      const bad=await req('GET','/api/'+resource+'/'+id,undefined,'invalid')
      assert.equal(bad.code,401)
      if(resource==='Cards') {
        assert.equal(legitimate.cardNum,'************3456')
        const list=ok(await req('GET','/api/Cards',undefined,owner.token))
        assert.equal(list.find(x=>x.id===id).cardNum,'************3456')
      }
    }
    result.properties[resource==='Addresss'?'address_owner':'card_owner']={reachable:true,
      legitimate_request:true,property_assertion:true,fresh_state:true,owner_identity:true,
      other_identity:true,owned_object:true,ownership:true,sessions_after:true}
  }
  result.properties.card_mask={reachable:true,legitimate_request:true,property_assertion:true,fresh_state:true}
  if(process.env.CFT_A03_REDIRECT==='1') {
    phase='redirect_property'
    // No redirect following or outbound network access. Check response headers only.
    const redirect = path => new Promise((resolve,reject)=>{
      const r=http.get({hostname:'127.0.0.1',port:3000,path},s=>{
        s.resume();s.on('end',()=>resolve({code:s.statusCode,location:s.headers.location}))
      });r.on('error',reject);r.setTimeout(3000,()=>r.destroy(new Error('timeout')))
    })
    const allowed='https://github.com/juice-shop/juice-shop'
    const good=await redirect('/redirect?to='+encodeURIComponent(allowed))
    assert.equal(good.code,302);assert.equal(good.location,allowed)
    for(const bad of ['https://example.invalid/?next='+allowed,allowed+'.example.invalid','javascript:'+allowed]) {
      const denied=await redirect('/redirect?to='+encodeURIComponent(bad))
      assert.equal(denied.code,406);assert.equal(denied.location,undefined)
    }
    const again=await redirect('/redirect?to='+encodeURIComponent(allowed))
    assert.equal(again.code,302)
    result.properties.redirect_exact={reachable:true,legitimate_request:true,property_assertion:true,fresh_state:true}
  }
  // Mutation survives within this experiment; next fresh container must reseed.
  assert.equal(ok(await req('GET','/api/Addresss',undefined,users[0].token)).length,1)
  console.log(JSON.stringify(result))
})().catch(()=>{console.error('A03 fixture assertion failed at '+phase);process.exit(1)})
