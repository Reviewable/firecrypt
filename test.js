
const fs = require('fs');
const path = require('path');
const admin = require('firebase-admin');
// const firebase = require('firebase');

// require('./dist/index');
const FireCrypt = require('./index');

/* TODO: specify the relative path to a service account key JSON file for your project */
const pathToserviceAccount = path.resolve(__dirname, './resources/serviceAccount.json');
if (!fs.existsSync(pathToserviceAccount)) {
  console.log(
    `[ERROR] Firebase service account not found. Please place it in ${pathToserviceAccount}.`
  );
  process.exit(1);
}

const serviceAccount = require(pathToserviceAccount);

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
  databaseURL: `https://${serviceAccount.project_id}.firebaseio.com`,
});

const options = {
  algorithm: 'passthrough',
};

const specification = {
  "rules": {
    "foo": {
      ".encrypt": {"value": "#"}
    },
    "bar": {
      "$baz": {
        ".encrypt": {"key": "#-#-."}
      }
    }
  }
};

const originalDb = admin.database;
// admin.database = new FireCrypt(originalDb(), options, specification);
otherDb = new FireCrypt(originalDb(), options, specification);

// console.log(admin.database);
// console.log(otherDb);

// Firebase.initializeEncryption(options, specification);

// const ref = new Firebase('https://consulting-scratchpad.firebaseio.com/foo');
// const db = admin.database();
const db = otherDb;
const ref = db.ref('/foo');

const pushedRef = ref.push();

// console.log(pushedRef.key());
console.log('KEYYYY:', pushedRef.key);
// pushedRef.onDisconnect().set('FOO', (error) => {
//   if (error) {
//     console.log('ERROR:', error);
//   } else {
//     console.log('on disconnect success!');
//   }
// });

pushedRef.push('foo', (error) => {
  if (error) {
    console.log('Failed to push:', error);
  } else {
    console.log('Successfully pushed');
    pushedRef.orderByKey().limitToLast(1).on('value', (snap) => {
      // console.log('Got snap:', snap.key(), snap.name(), snap.val());
      console.log('Got snap:', snap.key, snap.val());
      console.log('Num children:', snap.numChildren());
      console.log('Has children:', snap.hasChildren());
    }, (error) => {
      console.log('Failed to listen:', error);
    });    
  }
});
