'use strict';

/*
 * Decaffeinate suggestions:
 * DS101: Remove unnecessary use of Array.from
 * DS102: Remove unnecessary code created because of implicit returns
 * DS205: Consider reworking code to avoid use of IIFEs
 * DS207: Consider shorter variations of null checks
 * Full docs: https://github.com/decaffeinate/decaffeinate/blob/master/docs/suggestions.md
 */
const HMAC_SHA1 = require('./hmac-sha1');
const MemoryNonceStore = require('./memory-nonce-store');
const errors = require('./errors');
const extensions = require('./extensions');

const noop = () => undefined;

class Provider {
  /**
   * Creates an instance of Provider.
   *
   * @param {string} consumer_key Consumer key to validate request with
   * @param {string} consumer_secret Consumer secret to validate request with
   * @param {object} [optionsOrNonceStore] Options or nonce store
   * @param {object} [signature_method] HMAC-SHA1 signing object
   * @todo remove bound properties.
   */
  constructor(
    consumer_key,
    consumer_secret,
    optionsOrNonceStore,
    signature_method
  ) {
    this.valid_request = this.valid_request.bind(this);
    this.parse_request = this.parse_request.bind(this);

    if (consumer_key == null) {
      throw new errors.ConsumerError('Must specify consumer_key');
    }

    if (consumer_secret == null) {
      throw new errors.ConsumerError('Must specify consumer_secret');
    }

    let nonceStore, options;

    if (
      optionsOrNonceStore &&
      typeof optionsOrNonceStore.isNonceStore === 'function' &&
      optionsOrNonceStore.isNonceStore()
    ) {
      options = {};
      nonceStore = optionsOrNonceStore;
    } else {
      options = optionsOrNonceStore || {};
      nonceStore = options.nonceStore || new MemoryNonceStore();
    }

    if (!signature_method) {
      signature_method = options.signer || new HMAC_SHA1(options);
    }

    this.consumer_key = consumer_key;
    this.consumer_secret = consumer_secret;
    this.signer = signature_method;
    this.nonceStore = nonceStore;
    this.body = {};
  }

  /**
   * Verify parameter and OAuth signature by passing the request object.
   *
   * - sets up request variables for easier access down the line.
   * - returns true/false if is valid.
   *
   * @param {object} req HTTP request
   * @param {object} [body] HTTP request body
   * @param {function(err: Error, isValid: boolean): void} cb Called with error and result
   * @returns {boolean}
   */
  valid_request(req, ...args) {
    const [bodyArg, cb = noop] = args.length > 1 ? args : [undefined, ...args];
    const body = bodyArg || req.body || req.payload;

    if (!this._valid_parameters(body)) {
      cb(new errors.ParameterError('Invalid LTI parameters'), false);
      return false;
    }

    return this._valid_oauth(req, body, cb);
  }

  /**
   * Helper to validate basic LTI parameters
   *
   * Returns true/false if is valid LTI request
   *
   * @param {any} body Body to validate
   * @returns {boolean}
   */
  _valid_parameters(body) {
    if (!body) {
      return false;
    }

    const correct_version =
      require('./ims-lti').supported_versions.indexOf(body.lti_version) !== -1;
    const has_resource_link_id = body.resource_link_id != null;
    const omits_content_item_params =
      body.resource_link_id == null &&
      body.resource_link_title == null &&
      body.resource_link_description == null &&
      body.launch_presentation_return_url == null &&
      body.lis_result_sourcedid == null;

    return (
      (correct_version &&
        (body.lti_message_type === 'basic-lti-launch-request' &&
          has_resource_link_id)) ||
      (body.lti_message_type === 'ContentItemSelectionRequest' &&
        omits_content_item_params)
    );
  }

  /**
   * Helper to validate the OAuth information in the request.
   *
   * Report true/false if is valid OAuth signature and nonce.
   *
   * @param {object} req HTTP request
   * @param {object} body HTTP body
   * @param {function(e: Error, result: boolean)} callback Result handler
   * @returns {void}
   */
  _valid_oauth(req, body, callback) {
    const generated = this.signer.build_signature(
      req,
      body,
      this.consumer_secret
    );
    const valid_signature = generated === body.oauth_signature;

    console.log(generated, body.oauth_signature);
    
    if (!valid_signature) {
      return callback(new errors.SignatureError('Invalid Signature'), false);
    }

    this.nonceStore.isNew(
      body.oauth_nonce,
      body.oauth_timestamp,
      (err, valid) => {
        if (err != null || !valid) {
          return callback(new errors.NonceError('Expired nonce'), false);
        }

        return callback(null, true);
      }
    );
  }

  // Stores the request's properties into the @body accessor
  //  Strips 'oauth_' parameters for saftey
  //
  // Does not return anything
  parse_request(req, body) {
    body = body || req.body || req.payload;

    /* eslint-disable guard-for-in */
    for (const key in body) {
      const val = body[key];

      if (key.match(/^oauth_/)) {
        continue;
      }
      this.body[key] = val;
    }
    /* eslint-enable guard-for-in */

    if (typeof this.body.roles === 'string') {
      this.body.roles = this.body.roles.split(',');
    }

    this.admin = this.has_role('Administrator');
    this.alumni = this.has_role('Alumni');
    this.content_developer = this.has_role('ContentDeveloper');
    this.guest = this.has_role('Guest');
    this.instructor =
      this.has_role('Instructor') ||
      this.has_role('Faculty') ||
      this.has_role('Staff');
    this.manager = this.has_role('Manager');
    this.member = this.has_role('Member');
    this.mentor = this.has_role('Mentor');
    this.none = this.has_role('None');
    this.observer = this.has_role('Observer');
    this.other = this.has_role('Other');
    this.prospective_student = this.has_role('ProspectiveStudent');
    this.student = this.has_role('Learner') || this.has_role('Student');
    this.ta = this.has_role('TeachingAssistant');

    this.launch_request =
      this.body.lti_message_type === 'basic-lti-launch-request';

    // User
    this.username =
      this.body.lis_person_name_given ||
      this.body.lis_person_name_family ||
      this.body.lis_person_name_full ||
      '';
    this.userId = this.body.user_id;

    if (typeof this.body.role_scope_mentor === 'string') {
      this.mentor_user_ids = Array.from(
        this.body.role_scope_mentor.split(',')
      ).map(id => decodeURIComponent(id));
    }

    // Context information
    this.context_id = this.body.context_id;
    this.context_label = this.body.context_label;
    this.context_title = this.body.context_title;

    // Load up the extensions!
    /* eslint-disable guard-for-in */
    for (const extension_name in extensions) {
      extensions[extension_name].init(this);
    }
    /* eslint-enable guard-for-in */
  }

  // Has_role Helper
  has_role(role) {
    // There's 3 different types of roles: system, institution, and context. Each one has their own unique identifier
    // string within the urn prefix. This regular expression can verify the prefix is there at all, and if it is, ensure
    // that it matches one of the three different ways that it can be formatted. Additionally, context roles can have a
    // suffix that futher describes what the role may be (such as an instructor that is a lecturer). Those details are
    // probably a bit too specific for most cases, so we can just verify that they are optionally there.
    const regex = new RegExp(
      `^(urn:lti:(sys|inst)?role:ims/lis/)?${role}(/.+)?$`,
      'i'
    );

    return this.body.roles && this.body.roles.some(r => regex.test(r));
  }
}

module.exports = Provider;
