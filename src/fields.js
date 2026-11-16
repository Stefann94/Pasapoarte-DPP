/*
 * Common passport fields, used for portal forms and for translated labels on
 * the public page. This is a practical subset inspired by Annex XIII of
 * Regulation (EU) 2023/1542, not an authoritative list: clients can always add
 * further fields, and the field list must be validated against the
 * Commission's official data model before relying on it for compliance.
 *
 * level: 'model' = same for every battery of a model, 'item' = per battery.
 */
export const FIELDS = [
  // ---- public, model level
  { key: 'manufacturer', section: 'public', level: 'model', ro: 'Producător', en: 'Manufacturer' },
  { key: 'manufacturerAddress', section: 'public', level: 'model', ro: 'Adresa producătorului', en: "Manufacturer's address" },
  { key: 'manufacturerIdentifier', section: 'public', level: 'model', ro: 'Identificatorul producătorului', en: 'Manufacturer identifier' },
  { key: 'manufacturingPlace', section: 'public', level: 'model', ro: 'Locul fabricației', en: 'Place of manufacture' },
  { key: 'batteryModel', section: 'public', level: 'model', ro: 'Modelul bateriei', en: 'Battery model' },
  { key: 'chemistry', section: 'public', level: 'model', ro: 'Chimia bateriei', en: 'Battery chemistry' },
  { key: 'weightKg', section: 'public', level: 'model', ro: 'Greutate (kg)', en: 'Weight (kg)', type: 'number' },
  { key: 'ratedCapacityKWh', section: 'public', level: 'model', ro: 'Energie nominală (kWh)', en: 'Rated energy (kWh)', type: 'number' },
  { key: 'ratedCapacityAh', section: 'public', level: 'model', ro: 'Capacitate nominală (Ah)', en: 'Rated capacity (Ah)', type: 'number' },
  { key: 'nominalVoltageV', section: 'public', level: 'model', ro: 'Tensiune nominală (V)', en: 'Nominal voltage (V)', type: 'number' },
  { key: 'expectedLifetimeCycles', section: 'public', level: 'model', ro: 'Durată de viață estimată (cicluri)', en: 'Expected lifetime (cycles)', type: 'number' },
  { key: 'operatingTemperatureRange', section: 'public', level: 'model', ro: 'Interval de temperatură de funcționare', en: 'Operating temperature range' },
  { key: 'hazardousSubstances', section: 'public', level: 'model', ro: 'Substanțe periculoase', en: 'Hazardous substances', type: 'textarea' },
  { key: 'criticalRawMaterials', section: 'public', level: 'model', ro: 'Materii prime critice', en: 'Critical raw materials', type: 'textarea' },
  { key: 'carbonFootprint', section: 'public', level: 'model', ro: 'Amprenta de carbon', en: 'Carbon footprint' },
  { key: 'recycledContent', section: 'public', level: 'model', ro: 'Conținut reciclat', en: 'Recycled content' },
  { key: 'separateCollection', section: 'public', level: 'model', ro: 'Colectare separată și sfârșitul ciclului de viață', en: 'Separate collection and end of life', type: 'textarea' },
  { key: 'euDeclarationOfConformity', section: 'public', level: 'model', ro: 'Declarația UE de conformitate (link)', en: 'EU declaration of conformity (link)' },
  // ---- legitimate interest, model level
  { key: 'detailedComposition', section: 'legitimateInterest', level: 'model', ro: 'Compoziție detaliată (catod, anod, electrolit)', en: 'Detailed composition (cathode, anode, electrolyte)', type: 'textarea' },
  { key: 'sparePartNumbers', section: 'legitimateInterest', level: 'model', ro: 'Coduri piese de schimb și contact', en: 'Spare part numbers and contact', type: 'textarea' },
  { key: 'dismantlingInformation', section: 'legitimateInterest', level: 'model', ro: 'Informații de dezasamblare', en: 'Dismantling information', type: 'textarea' },
  { key: 'safetyMeasures', section: 'legitimateInterest', level: 'model', ro: 'Măsuri de siguranță', en: 'Safety measures', type: 'textarea' },
  // ---- authorities, model level
  { key: 'testReports', section: 'authorities', level: 'model', ro: 'Rapoarte de testare (referințe)', en: 'Test reports (references)', type: 'textarea' },
  { key: 'conformityAssessment', section: 'authorities', level: 'model', ro: 'Evaluarea conformității', en: 'Conformity assessment', type: 'textarea' },
  // ---- item level (per battery)
  { key: 'manufacturingDate', section: 'public', level: 'item', ro: 'Data fabricației', en: 'Manufacturing date', type: 'date' },
  { key: 'batteryStatus', section: 'public', level: 'item', ro: 'Starea bateriei (originală, reutilizată, remanufacturată...)', en: 'Battery status (original, repurposed, remanufactured...)' },
  { key: 'stateOfHealth', section: 'legitimateInterest', level: 'item', ro: 'Starea de sănătate (SoH)', en: 'State of health (SoH)' },
];

export const SECTIONS = [
  { key: 'public', ro: 'Informații publice', en: 'Public information' },
  { key: 'legitimateInterest', ro: 'Persoane cu interes legitim', en: 'Persons with a legitimate interest' },
  { key: 'authorities', ro: 'Autorități și organisme notificate', en: 'Authorities and notified bodies' },
];

const LABELS = new Map(FIELDS.map((f) => [f.key, f]));
export const fieldLabel = (key, lang) => LABELS.get(key)?.[lang] ?? key;
export const fieldsFor = (level, section) => FIELDS.filter((f) => f.level === level && f.section === section);
