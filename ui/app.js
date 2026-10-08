'use strict';
const $ = id => document.getElementById(id);
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const number = value => Number(value).toLocaleString('tr-TR', {maximumFractionDigits:2});
const state = {session:null, auth:'password', result:null, view:'overview', query:'', rule:'', page:0, sort:null, descending:true, busy:false};
const tableDefs = {
  candidates:{title:'Kural bazında inceleme',description:'Tekrar sayısına göre sıralıdır. Tekrar oranı, bu kuralın tetiklenmeleri içindeki tekrar payıdır.',columns:[['rule_name','Kural'],['count','Tetiklenme'],['percent','Toplam pay %'],['repeats','Tekrar'],['repeat_percent','Tekrar %'],['groups','Grup']]},
  repeats:{title:'Tekrar grupları',description:'Aynı kuralın sabit pencere içindeki tetiklenmeleri. Her grubun ilk kaydı hariç tekrar sayılır.',columns:[['rule_name','Kural'],['start','Başlangıç UTC'],['end','Son tetiklenme UTC'],['count','Tetiklenme'],['repeats','Tekrar']]},
  alerts:{title:'Tetiklenme kayıtları',description:'Seçilen zaman aralığındaki geçerli tetiklenmeler. Tüm zamanlar UTC.',columns:[['_time','Zaman UTC'],['rule_name','Kural']]},
  rejected:{title:'Atlanan kayıtlar',description:'Girdi kayıt sırası ve atlama nedeni. CSV başlığı kayıt sayılmaz.',columns:[['row','Kayıt sırası'],['reason','Neden']]}
};

function message(text,type='info') {
  $('notice').hidden=false;$('notice').className='notice '+type;$('notice').textContent=text;
}
async function request(path,data) {
  const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-Analyzer-Token':document.querySelector('meta[name=session-token]').content},body:JSON.stringify(data)});
  const result=await response.json();
  if(response.status===401)setSession(null);
  if(!response.ok)throw new Error(result.error||'İşlem tamamlanamadı.');
  return result;
}
async function perform(text,action) {
  if(state.busy)return;
  state.busy=true;document.body.setAttribute('aria-busy','true');syncReady();
  $('footer-status').textContent='İşlem sürüyor';message(text);
  try{await action();}catch(error){message(error.message,'error');}
  finally{state.busy=false;document.body.removeAttribute('aria-busy');$('footer-status').textContent='Hazır';syncReady();if(state.result&&state.view!=='overview')renderTable();}
}
function syncReady() {
  $('connection-fields').disabled=state.busy||!!state.session;
  $('connect').disabled=state.busy||!!state.session;
  $('disconnect').disabled=state.busy||!state.session;
  $('run').disabled=state.busy||!state.session;
  ['earliest','latest','window'].forEach(id=>$(id).disabled=state.busy);
  document.querySelectorAll('[data-view]').forEach(b=>b.disabled=state.busy);
}
function clearResults() {
  state.result=null;['count-total','count-rules','count-repeats','count-ratio'].forEach(id=>$(id).textContent='—');
  $('total-detail').textContent='Seçilen zaman aralığında';$('repeat-detail').textContent='Her grubun ilk kaydı hariç';
  ['download-links','result-toolbar','overview','table-panel'].forEach(id=>$(id).hidden=true);$('results-empty').hidden=false;
  $('checked-at').textContent="Splunk'a bağlanıp analizi başlattığında sonuçlar burada görünecek.";
  $('scope-note').textContent='Tekrarlar aynı kuralın kısa aralıklarla yeniden tetiklenmesidir. İnceleme adayıdır; otomatik false positive kararı verilmez.';
}
function auth(mode) {
  state.auth=mode;
  ['password','token'].forEach(item=>{$(item+'-auth').classList.toggle('selected',item===mode);$(item+'-auth').setAttribute('aria-pressed',String(item===mode));$(item+'-fields').hidden=item!==mode;});
  $('username').required=mode==='password';$('password').required=mode==='password';$('token').required=mode==='token';
  $('password').value='';$('token').value='';
}
function setSession(session) {
  state.session=session&&session.connected?session:null;
  $('connection-status').textContent=state.session?'Splunk bağlantısı hazır':'Bağlantı bekleniyor';
  $('connection-status').className='badge '+(state.session?'ok':'neutral');
  $('connect').querySelector('span').textContent=state.session?'Bağlandı':'Bağlan';
  $('connection-note').textContent=state.session?`${state.session.base_url} · ${state.session.auth_mode==='token'?'Token':'Kullanıcı / parola'} · Oturum sonu ${new Date(state.session.expires_at).toLocaleTimeString('tr-TR',{timeZone:'UTC'})} UTC`:'Parola/token yalnızca sunucu belleğinde tutulur. Oturum 1 saat sonra sona erer.';
  $('password').value='';$('token').value='';
  if(state.session){
    auth(state.session.auth_mode);$('address').value=state.session.base_url;$('tls').checked=state.session.verify_tls;
  }else{clearResults();}
  $('tls-warning').hidden=$('tls').checked;syncReady();
}
function connection() {
  return {base_url:$('address').value.trim(),auth_mode:state.auth,
    username:state.auth==='password'?$('username').value.trim():'',password:state.auth==='password'?$('password').value:'',
    token:state.auth==='token'?$('token').value.trim():'',verify_tls:$('tls').checked,ca_bundle:$('ca-bundle').value.trim()};
}
function reportUrl(name){return `/reports/${state.result.id}/${name}`;}
function bars(rows,label,max=6) {
  const shown=rows.slice(0,max);const high=Math.max(...shown.map(row=>row.count),1);
  return shown.length?shown.map(row=>`<div class="bar"><span class="bar-label" title="${esc(row[label])}">${esc(row[label])}</span><div class="track"><i style="width:${100*row.count/high}%"></i></div><b>${number(row.count)}${row.percent===undefined?'':` <small>%${number(row.percent)}</small>`}</b></div>`).join(''):'<p class="no-data">Bu kapsamda kayıt yok.</p>';
}
function hours(rows) {
  if(!rows.length)return '<p class="no-data">Bu kapsamda kayıt yok.</p>';
  const high=Math.max(...rows.map(row=>row.count),1),width=500,height=120,base=145;
  const points=rows.map((row,i)=>[35+(width-55)*(rows.length===1?.5:i/(rows.length-1)),base-(row.count/high)*height]);
  const line=points.map(point=>point.join(',')).join(' ');
  const grid=[0,.5,1].map(f=>`<line x1="35" y1="${base-height*f}" x2="495" y2="${base-height*f}" stroke="#e5e9eb"/><text x="25" y="${base-height*f+4}" text-anchor="end" fill="#718088" font-size="10">${number(Math.round(high*f))}</text>`).join('');
  const dots=points.map(([x,y],i)=>`<circle cx="${x}" cy="${y}" r="${rows.length>60?1.5:3.5}" fill="#e8572b"><title>${esc(rows[i].hour_utc)} · ${rows[i].count} kayıt</title></circle>`).join('');
  return `<svg class="hour-svg" viewBox="0 0 510 170" role="img" aria-label="UTC saatlik alarm sayısı">${grid}<polygon points="${points[0][0]},${base} ${line} ${points[points.length-1][0]},${base}" fill="#fff1eb"/><polyline points="${line}" fill="none" stroke="#e8572b" stroke-width="2"/>${dots}</svg><div class="chart-caption"><span>${esc(rows[0].hour_utc.slice(0,16))}</span><span>${esc(rows[rows.length-1].hour_utc.slice(0,16))}</span></div><p class="hint">${rows.length} dolu saat; sıfır saatler gösterilmez. Noktalar dolu saat sırasıyla çizilir.</p>`;
}
function receive(result) {
  state.result=result;const report=result.report,s=report.summary[0],total=s.total_alerts;
  $('checked-at').textContent=`${new Date(result.created).toLocaleString('tr-TR',{timeZone:'UTC'})} UTC · ${number(result.metadata.window_minutes)} dk pencere`;
  $('scope-note').textContent=result.metadata.scope+' Tekrarlar yalnızca inceleme adayıdır.';
  $('count-total').textContent=number(total);$('count-rules').textContent=number(result.counts.rules);
  $('count-repeats').textContent=number(s.repeat_alerts);$('count-ratio').textContent='%'+number(total?s.repeat_alerts*100/total:0);
  $('total-detail').textContent=[`${number(s.input_rows)} alınan`,s.skipped_rows?`${number(s.skipped_rows)} atlanan`:'',s.filtered_rows?`${number(s.filtered_rows)} zaman dışı`:''].filter(Boolean).join(' · ');
  $('repeat-detail').textContent=`${number(s.repeat_groups)} tekrar grubu`;
  $('rule-chart').innerHTML=bars(report.rules,'rule_name',10);$('hour-chart').innerHTML=hours(report.hourly);
  $('html-link').href=reportUrl('dashboard.html');$('zip-link').href=reportUrl('report.zip');
  $('rule-filter').innerHTML='<option value="">Tüm kurallar</option>'+report.rules.map(row=>`<option value="${esc(row.rule_name)}">${esc(row.rule_name)}</option>`).join('');
  $('results-empty').hidden=true;$('download-links').hidden=false;$('result-toolbar').hidden=false;
  setView('overview');message(total?'Analiz tamamlandı. Raporları indirebilir veya tabloları inceleyebilirsin.':'Bu aralıkta görünür tetiklenme bulunamadı. Takip ayarı, saklama süresi ve erişim yetkisi sonucu etkiler.');
}
function setView(view) {
  state.view=view;state.page=0;state.query='';state.rule='';state.sort=null;$('table-search').value='';$('rule-filter').value='';
  document.querySelectorAll('[data-view]').forEach(button=>{button.classList.toggle('selected',button.dataset.view===view);button.setAttribute('aria-pressed',String(button.dataset.view===view));});
  $('overview').hidden=view!=='overview';$('table-panel').hidden=view==='overview';if(view!=='overview')renderTable();
}
function renderTable() {
  const def=tableDefs[state.view];if(!def || !state.result)return;
  $('table-title').textContent=def.title;$('table-description').textContent=def.description;$('table-download').href=reportUrl(state.view+'.csv');
  $('rule-filter').hidden=state.view==='rejected';
  let rows=state.result.report[state.view].filter(row=>(!state.rule||row.rule_name===state.rule)&&(!state.query||Object.values(row).some(value=>String(value).toLocaleLowerCase('tr').includes(state.query))));
  if(state.sort)rows=[...rows].sort((a,b)=>{const x=a[state.sort],y=b[state.sort];const order=typeof x==='number'&&typeof y==='number'?x-y:String(x).localeCompare(String(y),'tr');return state.descending?-order:order;});
  const pages=Math.max(1,Math.ceil(rows.length/25));state.page=Math.min(state.page,pages-1);
  const subset=rows.slice(state.page*25,(state.page+1)*25);
  const cell=(key,value)=>esc(typeof value==='number'?number(value):value);
  $('result-table').innerHTML=`<table class="result-table"><thead><tr>${def.columns.map(([key,label])=>`<th><button data-sort="${key}" title="Sırala">${esc(label)} ${state.sort===key?(state.descending?'↓':'↑'):'↕'}</button></th>`).join('')}</tr></thead><tbody>${subset.map(row=>`<tr>${def.columns.map(([key])=>`<td title="${esc(row[key])}">${cell(key,row[key])}</td>`).join('')}</tr>`).join('')}</tbody></table>${rows.length?'':'<div class="no-data">Bu filtrelere uygun kayıt yok.</div>'}`;
  $('result-table').querySelectorAll('[data-sort]').forEach(button=>button.addEventListener('click',()=>{state.descending=state.sort===button.dataset.sort?!state.descending:true;state.sort=button.dataset.sort;state.page=0;renderTable();}));
  $('table-count').textContent=`${number(rows.length)} eşleşme`;$('page-label').textContent=`${state.page+1} / ${pages}`;
  $('previous').disabled=state.busy||state.page===0;$('next').disabled=state.busy||state.page>=pages-1;
  const shown=state.result.report[state.view].length,all=state.result.counts[state.view];
  $('table-limit').textContent=`Arama ${number(shown)} yüklenen satır üzerinde çalışır. Toplam ${number(all)} satır; tamamı CSV’de. Filtreler özet kartlarını değiştirmez.`;
}

document.querySelectorAll('[data-view]').forEach(button=>button.addEventListener('click',()=>setView(button.dataset.view)));
$('password-auth').addEventListener('click',()=>auth('password'));
$('token-auth').addEventListener('click',()=>auth('token'));
$('tls').addEventListener('change',()=>{$('tls-warning').hidden=$('tls').checked;});
$('connect-form').addEventListener('submit',event=>{
  event.preventDefault();perform('TCP, TLS ve Splunk okuma erişimi kontrol ediliyor…',async()=>{
    const result=await request('/api/connect',connection());clearResults();setSession(result);
    message('Splunk hesabı doğrulandı. Zaman aralığını seçip analizi çalıştırabilirsin.');
  });
});
$('disconnect').addEventListener('click',()=>perform('Oturum kapatılıyor…',async()=>{
  await request('/api/disconnect',{});setSession(null);$('username').value='';message('Bağlantı kesildi. Giriş bilgileri sunucu belleğinden silindi.');
}));
$('run').addEventListener('click',()=>perform('Tetiklenmeler alınıyor, analiz hazırlanıyor…',async()=>{
  receive(await request('/api/analyze',{window:$('window').value,earliest:$('earliest').value.trim(),latest:$('latest').value.trim()}));
}));
$('table-search').addEventListener('input',()=>{state.query=$('table-search').value.toLocaleLowerCase('tr');state.page=0;renderTable();});
$('rule-filter').addEventListener('change',()=>{state.rule=$('rule-filter').value;state.page=0;renderTable();});
$('previous').addEventListener('click',()=>{state.page--;renderTable();});$('next').addEventListener('click',()=>{state.page++;renderTable();});
async function restoreSession(){
  try{const response=await fetch('/api/session');if(!response.ok)throw new Error();setSession(await response.json());}
  catch{setSession(null);message('Yerel uygulamaya ulaşılamadı. Terminalde app.py çalıştığından emin ol.','error');}
}
restoreSession();
setInterval(()=>{if(state.session&&!state.busy&&Date.now()>=Date.parse(state.session.expires_at)){setSession(null);message('Oturum süresi doldu. Yeniden bağlan.','error');}},10000);
