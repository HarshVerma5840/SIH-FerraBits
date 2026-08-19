export const MOCK_DATA = {
  packages: [
    { id: 'pkg1', name: 'package abc', isVulnerable: true },
    { id: 'pkg2', name: 'package xyz', isVulnerable: false },
    { id: 'pkg3', name: 'package efg', isVulnerable: false },
    { id: 'pkg4', name: 'package lmn', isVulnerable: false },
    { id: 'pkg5', name: 'package opq', isVulnerable: false },
    { id: 'pkg6', name: 'package rst', isVulnerable: false },
    { id: 'pkg7', name: 'package uvw', isVulnerable: false },
    { id: 'pkg8', name: 'package hij', isVulnerable: false },
    { id: 'pkg9', name: 'package klm', isVulnerable: false },
    { id: 'pkg10', name: 'package nop', isVulnerable: false },
  ],
  methods: [
    { id: 'm1', name: 'get()' },
    { id: 'm2', name: 'save()' },
    { id: 'm3', name: 'delete()' },
  ],
  occurrences: {
    'm1': [
      { id: 'occ_m1_1', name: '12. get(ferrabite, 50)' },
      { id: 'occ_m1_2', name: '55. get(data, 10)' },
      { id: 'occ_m1_3', name: '89. get(cache, 5)' },
    ],
    'm2': [
      { id: 'occ_m2_1', name: '10. save(ferrabite, 100)' },
      { id: 'occ_m2_2', name: '42. save(data, 20)' },
      { id: 'occ_m2_3', name: '88. save(cache, 15)' },
    ],
    'm3': [
      { id: 'occ_m3_1', name: '3. delete(ferrabite)' },
      { id: 'occ_m3_2', name: '21. delete(temp)' },
      { id: 'occ_m3_3', name: '44. delete(logs)' },
      { id: 'occ_m3_4', name: '99. delete(old_cache)' },
    ]
  },
  dependencies: {
    // get() occurrences
    'occ_m1_1': [{ id: 'dep_1', name: 'fetchData()' }, { id: 'dep_2', name: 'parse(ferrabite)' }],
    'occ_m1_2': [{ id: 'dep_3', name: 'readStream()' }],
    'occ_m1_3': [{ id: 'dep_4', name: 'checkMemory()' }, { id: 'dep_5', name: 'loadCache()' }],
    
    // save() occurrences
    'occ_m2_1': [{ id: 'dep_6', name: 'commit()' }, { id: 'dep_7', name: 'get(ferrabite)' }],
    'occ_m2_2': [{ id: 'dep_8', name: 'validate(data)' }, { id: 'dep_9', name: 'writeDisk()' }],
    'occ_m2_3': [{ id: 'dep_10', name: 'serialize()' }],

    // delete() occurrences
    'occ_m3_1': [{ id: 'dep_11', name: 'unlink(ferrabite)' }],
    'occ_m3_2': [{ id: 'dep_12', name: 'clearTemp()' }, { id: 'dep_13', name: 'gc()' }],
    'occ_m3_3': [{ id: 'dep_14', name: 'truncateLogs()' }],
    'occ_m3_4': [{ id: 'dep_15', name: 'flushCache()' }, { id: 'dep_16', name: 'restart()' }],
  }
};
