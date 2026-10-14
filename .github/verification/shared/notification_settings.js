'use strict';
// Shared behavior is exercised for both packaged role assets.
function mountNotificationSettings(root, request, commandId) {
 const make=(tag,text)=>{const n=document.createElement(tag);if(text!==undefined)n.textContent=text;return n;};
 const title=make('h2','Уведомления'),form=make('form'),diagnostic=make('p'),fields={};
 const labels={enabled:'Включить уведомления',ha:'Показывать в Home Assistant',funds_low:'Не хватит на следующее продление',access_ending:'Доступ скоро закончится',access_stopped:'Доступ закончился из-за оплаты или срока',access_recovered:'Доступ восстановлен',connection:'Нет связи 10 минут / связь восстановлена'};
 for(const [key,label] of Object.entries(labels)){const wrap=make('label'),input=make('input');input.type='checkbox';fields[key]=input;wrap.append(input,make('span',label));form.append(wrap);}
 const days=make('input');days.type='number';days.min='1';days.max='30';days.required=true;fields.warning_days=days;
 const daysLabel=make('label','Предупредить за сколько дней (1–30)');daysLabel.append(days);form.append(daysLabel);
 const targets=make('select');targets.multiple=true;targets.size=4;
 const targetLabel=make('label','Телефон: выберите до 8 служб своего HA (необязательно)');targetLabel.append(targets);form.append(targetLabel);
 const submit=make('button','Сохранить уведомления');submit.type='submit';
 const testButton=make('button','Проверить доставку');testButton.type='button';
 const reload=make('button','Обновить форму');reload.type='button';reload.className='secondary';
 form.append(submit,testButton,reload);
 root.append(title,form,diagnostic,make('p','Настройки действуют только в этом HA. После перезапуска Core активная незакрытая карточка восстанавливается. Закрытие при отключённом наблюдателе может быть не замечено. Телефон обновляет карточку по tag; повторный звук зависит от Companion и ОС.'));
 let revision=null,csrf='',pending=null,pendingTest=null,busy=false;
 function status(code){diagnostic.textContent=code==='storage_error'?'Локальный журнал уведомлений повреждён. Исходный файл сохранён; уведомления остановлены.':code==='capacity'?'Достигнут лимит уведомлений. Доставка продолжится после освобождения очереди.':code==='mobile_catalog_unavailable'?'Список служб телефона временно недоступен. Сохранённые получатели оставлены.':code?'Уведомления временно недоступны. Подключение туннеля работает независимо.':'';}
 function render(data){
  revision=data.revision;csrf=data.csrf||csrf;
  for(const [key,input] of Object.entries(fields)){if(key==='warning_days')input.value=String(data.settings[key]);else input.checked=data.settings[key];}
  targets.replaceChildren();const valid=s=>typeof s==='string'&&/^notify\.mobile_app_[a-z0-9_]{1,128}$/.test(s);
  const selected=data.settings.mobile_targets.filter(valid),services=[...new Set([...(data.services||[]).filter(valid),...selected])].slice(0,520);
  for(const service of services){const option=make('option',service);option.value=service;option.selected=selected.includes(service);targets.append(option);}
  status(data.diagnostic);submit.disabled=!!data.diagnostic&&data.diagnostic==='storage_error';testButton.disabled=submit.disabled;
 }
 async function load(){try{const response=await request('api/notifications');if(!response.ok)throw Error();render(await response.json());pending=null;pendingTest=null;}catch{diagnostic.textContent='Не удалось загрузить уведомления. Откройте панель через Home Assistant и обновите форму.';}}
 async function post(path,body){
  const response=await request(path,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrf},body:JSON.stringify(body)});
  if(!response.ok){const error=new Error(response.status===409?'Настройки изменились. Обновите форму.':'Не удалось применить настройки. Проверьте выбранные службы.');error.definite=response.status>=400&&response.status<500;throw error;}
  return response.json();
 }
 async function save(event){event.preventDefault();if(busy||revision===null)return;busy=true;
  try{
   if(!pending){const settings={};for(const [key,input] of Object.entries(fields))settings[key]=key==='warning_days'?Number(input.value):input.checked;
    settings.mobile_targets=targets.children?Array.from(targets.children).filter(n=>n.selected).map(n=>n.value):[];
    if(!Number.isInteger(settings.warning_days)||settings.warning_days<1||settings.warning_days>30||settings.mobile_targets.length>8){diagnostic.textContent='Выберите 1–30 дней и не более 8 телефонов.';return;}
    pending={settings,revision,command_id:commandId()};
   }
   const result=await post('api/notifications',pending);revision=result.revision;pending=null;diagnostic.textContent='Настройки уведомлений сохранены.';
  }catch(error){diagnostic.textContent=error.definite?error.message:'Ответ не получен. Повторите сохранение — будет использована та же команда.';if(error.definite)pending=null;}
  finally{busy=false;submit.textContent=pending?'Повторить сохранение':'Сохранить уведомления';}
 }
 async function test(){if(busy||revision===null)return;busy=true;try{pendingTest=pendingTest||{revision,command_id:commandId()};await post('api/notifications/test',pendingTest);pendingTest=null;diagnostic.textContent='Проверка поставлена в очередь для сохранённых каналов.';}catch(error){diagnostic.textContent=error.definite?error.message:'Ответ не получен. Повторите проверку той же командой.';if(error.definite)pendingTest=null;}finally{busy=false;}}
 form.addEventListener('submit',save);testButton.addEventListener('click',test);reload.addEventListener('click',load);
 return {load,save,test,fields,targets,diagnostic};
}
if(typeof document!=='undefined'){
 const notificationRoot=document.getElementById('notification-settings');
 if(notificationRoot)mountNotificationSettings(notificationRoot,fetch,()=>{const bytes=new Uint8Array(16);crypto.getRandomValues(bytes);return Array.from(bytes,n=>n.toString(16).padStart(2,'0')).join('');}).load();
}
