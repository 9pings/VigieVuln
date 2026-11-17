'use strict';

const {renderTime}=require('../report-time');
const esc=value=>String(value??'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const tr=locale=>(en,fr)=>locale==='fr'?fr:en;
function observation(artifact) {
 const value=artifact?.imageUpdate;
 return value && ['available','current'].includes(value.status) && value.targetTag && value.targetReference ? value : null;
}

// Registry observations identify a release candidate, not a vulnerability verdict.
// The row names the action; the evidence panel explains its limits and provenance.
function renderImageCveAction(match,artifact,locale='en') {
 const t=tr(locale),update=observation(artifact);
 let action;
 if(update?.status==='available') {
  action=`<strong>${update.reasonCode==='rebuilt-tag'?t('Update rebuilt image','Actualiser l’image reconstruite'):t('Update image','Mettre à jour l’image')}</strong><br><code>${esc(update.targetReference)}</code>`;
 } else if(update?.status==='current') {
  action=`<strong>${t('Change branch or rebuild the image','Changer de branche ou reconstruire l’image')}</strong>`;
 } else {
  action=`<strong>${t('Update or rebuild the image','Mettre à jour ou reconstruire l’image')}</strong>`;
 }
 const fix=match.cve?.fixVersion||match.fixVersion;
 if(fix) {
  action+=`<small>${t('Component:','Composant :')} <code>${esc(fix)}</code></small>`;
 }
 return action;
}

function renderImageUpdateSummary(artifact,locale='en') {
 const t=tr(locale),update=observation(artifact),raw=artifact?.imageUpdate;
 let text;
 if(update) {
  text=`${t('Latest image observed in branch','Dernière image observée de la branche')} <code>${esc(update.branch)}</code> : <code>${esc(update.targetReference)}</code>. `;
  if(update.status==='current')text+=t('No newer comparable version was observed. Use a maintained branch or rebuild with updated packages and binaries.','Aucune version comparable plus récente n’a été observée. Choisissez une branche maintenue ou reconstruisez avec les paquets et binaires mis à jour.')+' ';
  if(update.reasonCode==='rebuilt-tag')text+=t('The tag is unchanged but its platform manifest digest differs from the scanned image.','Le tag est inchangé, mais l’empreinte de son manifeste de plateforme diffère de l’image analysée.')+' ';
  text+=t('The registry tag does not establish that the vulnerabilities are fixed; scan the replacement image.','Le tag du registre ne prouve pas que les vulnérabilités sont corrigées ; analysez l’image de remplacement.');
  if(update.observedAt)text+=`<br>${t('Registry consulted on','Registre consulté le')} ${renderTime(update.observedAt,locale)}.`;
  if(update.targetDigest)text+=`<br>${t('Candidate manifest digest','Empreinte du manifeste proposé')} : <code>${esc(update.targetDigest)}</code>`;
  if(update.platformDigest && update.platformDigest!==update.targetDigest)text+=`<br>${t('Candidate platform manifest digest','Empreinte du manifeste de plateforme proposé')} : <code>${esc(update.platformDigest)}</code>`;
 } else {
  text=t('No replacement tag or digest has been verified. Update the publisher image, or update the affected packages and binaries and rebuild the image.','Aucun tag ni empreinte de remplacement n’a été vérifié. Mettez à jour l’image de l’éditeur, ou mettez à jour les paquets et binaires concernés puis reconstruisez l’image.');
  if(raw?.reason && raw.reasonCode!=='no-reference')text+=`<br>${esc(raw.reason)}`;
 }
 return `<div class="image-update-evidence">${text}</div>`;
}

module.exports={renderImageCveAction,renderImageUpdateSummary};
