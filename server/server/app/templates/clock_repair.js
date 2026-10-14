"use strict";
function parseRepairInstant(value) {
 if(!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?(?:Z|[+-]\d{2}:\d{2})$/.test(value))throw new Error('Укажите дату, время и смещение: 2026-10-15T10:00:00+03:00');
 const seconds=Date.parse(value)/1000;
 if(!Number.isFinite(seconds))throw new Error('Неверная дата');
 return seconds;
}
function renderClockRepair(preview) {
 const root=byId('clock-result');root.replaceChildren();
 root.append(element('p','Сохранённая дата: '+date(preview.old_anchor)),element('p','Подтверждённая дата: '+date(preview.confirmed_now)));
 root.append(element('p',preview.confirmed_snapshot?'Синхронизация времени подтверждена Home Assistant.':'Ожидаем три стабильных подтверждения времени от Home Assistant. Платный доступ временно закрыт.'));
 if(preview.repair_allowed===true){
  const payload={command_id:commandId(),revision:preview.revision,confirmed_snapshot:preview.confirmed_snapshot};
  button(root,'Исправить сохранённую дату',async()=>{
   if(!confirm('Исправить дату '+date(preview.old_anchor)+' на '+date(preview.confirmed_now)+'? Будущие оплаченные периоды потребуют отдельной сверки. Балансы и покупки сохранятся.'))return;
   await api('api/clock/repair',payload);notify('Дата исправлена. Проверьте оплаченные периоды.');await loadClockRepair();
  });
 }
 for(const client of preview.clients.filter(c=>c.hold)){
  const form=element('form');form.append(element('h3',client.domain+' · требуется сверка периода'));
  form.append(element('p','Баланс: '+(client.balance_kopecks/100).toFixed(2)+' ₽. Прежний период: '+date(client.paid_from,client.timezone)+' — '+date(client.paid_until,client.timezone)));
  form.append(element('p','Исходные покупки: '+client.operation_ids.join(', ')));
  form.append(element('p','Новый период должен включать текущую подтверждённую дату. Укажите даты со смещением UTC, например 2026-10-15T10:00:00+03:00.'));
  const fields={};
  for(const [key,label,value] of [['paid_from','Начало периода',''],['paid_until','Конец периода',''],['timezone','Часовой пояс',client.timezone],['reason','Причина сверки','']]){
   const wrap=element('label',label),input=element('input');input.required=true;input.value=value;input.maxLength=key==='reason'?500:128;wrap.append(input);form.append(wrap);fields[key]=input;
  }
  let pending=null;
  button(form,'Проверить и подтвердить сверку',async()=>{
   const values={paid_from:parseRepairInstant(fields.paid_from.value),paid_until:parseRepairInstant(fields.paid_until.value),timezone:fields.timezone.value,reason:fields.reason.value.trim()};
   if(!values.reason)throw new Error('Укажите причину сверки.');
   const intent=JSON.stringify(values);
   if(!pending||pending.intent!==intent){
    const proposal=await(await api('api/clients/'+encodeURIComponent(client.client_id)+'/period-preview',{...values,revision:preview.revision,operation_ids:client.operation_ids})).json();
    pending={intent,proposal,payload:{...values,command_id:commandId(),revision:proposal.revision,operation_ids:proposal.operation_ids}};
   }
   const proposal=pending.proposal,old=proposal.old_period,next=proposal.new_period;
   if(!confirm('Сверка для '+client.domain+'\nПрежний период: '+date(old.paid_from,old.timezone)+' — '+date(old.paid_until,old.timezone)+'; день продления '+old.anchor_day+'\nНовый период: '+date(next.paid_from,next.timezone)+' — '+date(next.paid_until,next.timezone)+'; день продления '+next.anchor_day+'\nПричина: '+proposal.reason+'\nИсходные покупки: '+proposal.operation_ids.join(', ')+'\nБаланс останется '+(proposal.balance_kopecks/100).toFixed(2)+' ₽.'))return;
   await api('api/clients/'+encodeURIComponent(client.client_id)+'/period-reconciliation',pending.payload);
   notify('Период сверен. Баланс сохранён.');await loadClockRepair();
  });
  form.addEventListener('submit',event=>event.preventDefault());root.append(form);
 }
}
async function loadClockRepair(){renderClockRepair(await(await api('api/clock/preview')).json());}
byId('clock-load').addEventListener('click',()=>loadClockRepair().catch(e=>notify(e.message)));
