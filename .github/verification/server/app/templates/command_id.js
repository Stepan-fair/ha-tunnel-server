'use strict';
// UUIDv4 from the browser CSPRNG, also available in local HTTP contexts.
function commandId(){
 const bytes=new Uint8Array(16);
 crypto.getRandomValues(bytes);
 bytes[6]=(bytes[6]&0x0f)|0x40;
 bytes[8]=(bytes[8]&0x3f)|0x80;
 const hex=Array.from(bytes,byte=>byte.toString(16).padStart(2,'0')).join('');
 return hex.slice(0,8)+'-'+hex.slice(8,12)+'-'+hex.slice(12,16)+'-'+hex.slice(16,20)+'-'+hex.slice(20);
}

// A lost reply retries the original command; a confirmed conflict permits a fresh form.
async function administrativeCommand(holder,key,request,send){
 const payload=holder[key]||(holder[key]={...request,command_id:commandId()});
 try{const result=await send(payload);holder[key]=null;return result;}
 catch(error){if(error.status===409)holder[key]=null;throw error;}
}
