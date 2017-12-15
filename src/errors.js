'use strict';

class ConsumerError extends Error {}
class ExtensionError extends Error {}
class StoreError extends Error {}
class ParameterError extends Error {}
class SignatureError extends Error {}
class NonceError extends Error {}
class OutcomeResponseError extends Error {}

module.exports = {
  ConsumerError,
  ExtensionError,
  StoreError,
  ParameterError,
  SignatureError,
  NonceError,
  OutcomeResponseError
};
