/* Fixed evaluator-owned Docker-only assertions. No model/API capability. */
const http=require('node:http'),assert=require('node:assert/strict'),crypto=require('node:crypto')
const request=(method,path,data,token)=>new Promise((resolve,reject)=>{
  const body=data===undefined?'':JSON.stringify(data)
  const r=http.request({hostname:'127.0.0.1',port:3000,path,method,headers:{
    'Content-Type':'application/json','Content-Length':Buffer.byteLength(body),
    ...(token?{Authorization:'Bearer '+token,Cookie:'token='+token}:{})}},s=>{
      let text='';s.on('data',b=>{text+=b;if(text.length>262144)r.destroy(new Error('bounded response'))})
      s.on('end',()=>resolve({status:s.statusCode,location:s.headers.location,text}))
    });r.on('error',reject);r.setTimeout(3000,()=>r.destroy(new Error('timeout')));r.end(body)
})
const data=r=>{assert.equal(r.status,200);return JSON.parse(r.text).data}
const available=async()=>assert(data(await request('GET','/rest/products/search?q=Apple')).length>0)
;(async()=>{
  await available()
  if(process.env.CFT_A031_CASE==='redirect') {
    const url='https://github.com/juice-shop/juice-shop'
    const legitimate=await request('GET','/redirect?to='+encodeURIComponent(url))
    assert.equal(legitimate.status,302);assert.equal(legitimate.location,url)
    for(const denied of ['http://example.invalid?to='+url,url+'/issues',url+'.example.invalid','javascript:'+url]) {
      const result=await request('GET','/redirect?to='+encodeURIComponent(denied))
      assert.equal(result.status,406);assert.equal(result.location,undefined)
    }
    const after=await request('GET','/redirect?to='+encodeURIComponent(url))
    assert.equal(after.status,302);assert.equal(after.location,url)
    await available()
    console.log(JSON.stringify({reachable:true,legitimate:true,negative_assertion:true,post_available:true,followed_redirect:false}))
  } else {
    const email='cft-a031-review@example.invalid',password=crypto.randomBytes(32).toString('base64url')
    const created=await request('POST','/api/Users',{email,password,passwordRepeat:password})
    assert.equal(created.status,201)
    const id=JSON.parse(created.text).data.id
    const login=await request('POST','/rest/user/login',{email,password})
    assert.equal(login.status,200)
    const token=JSON.parse(login.text).authentication.token
    const identity=async()=>{
      const who=await request('GET','/rest/user/whoami',undefined,token)
      assert.equal(who.status,200);const user=JSON.parse(who.text).user
      assert.equal(user.id,id);assert.equal(user.email,email)
    }
    await identity()
    const added=await request('PUT','/rest/products/1/reviews',{author:email,message:'a031-own-before'},token)
    assert.equal(added.status,201)
    const get=async()=>data(await request('GET','/rest/products/1/reviews',undefined,token))
    const rows=await get(),own=rows.find(x=>x.author===email&&x.message==='a031-own-before')
    assert(own && typeof own._id==='string')
    const changed=await request('PATCH','/rest/products/reviews',{id:own._id,message:'a031-own-after'},token)
    assert.equal(changed.status,200);assert.equal(JSON.parse(changed.text).modified,1)
    const state=rows=>JSON.stringify(rows.map(x=>[x._id,x.message]).sort())
    const baseline=state(await get())
    for(const invalid of [{'$ne':null},123,null]) {
      const blocked=await request('PATCH','/rest/products/reviews',{id:invalid,message:'a031-forbidden'},token)
      assert.equal(blocked.status,400);assert.equal(state(await get()),baseline)
    }
    await identity()
    const again=await request('PATCH','/rest/products/reviews',{id:own._id,message:'a031-still-available'},token)
    assert.equal(again.status,200);assert.equal(JSON.parse(again.text).modified,1)
    await available()
    console.log(JSON.stringify({reachable:true,identity:true,resource_exists:true,legitimate:true,negative_assertion:true,post_available:true,post_identity:true}))
  }
})().catch(()=>{console.error('A03.1 independent oracle or availability precondition failed');process.exit(1)})
