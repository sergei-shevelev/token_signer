# frozen_string_literal: true

require 'base64'

RSpec.describe TokenSigner do
  def expect_signed_data_to_be_valid(instance, signed_data)
    check_validity_of_signed_data(instance, signed_data, valid: true, invalid: false)
  end
  def expect_signed_data_to_be_invalid(instance, signed_data)
    check_validity_of_signed_data(instance, signed_data, valid: false, invalid: true)
  end
  def check_validity_of_signed_data(instance, signed_data, valid:, invalid:)
    valid_block_called = false
    invalid_block_called = false

    instance.from_signed_string(signed_data).when_valid {
      valid_block_called = true
    }.when_invalid do
      invalid_block_called = true
    end

    aggregate_failures do
      expect(valid_block_called).to be(valid)
      expect(invalid_block_called).to be(invalid)
    end
  end

  let(:_SignedData) { described_class.const_get(:SignedData) }
  let(:secret) { 'kUWEAukw5RukgA4sETcCa996' }
  let(:unix_time) { Time.mktime(2020, 12, 28, 17, 10, 47).to_i }

  let(:string_payload) { 'V3AE5k8U4CosyZdTaQHB45j5' }
  let(:string_payload_encoded) { build_encoded_payload(string_payload, unix_time).freeze }
  let(:string_payload_sig) { '3e53d41b584ded257670da2faf7421168d0b2332' }
  let(:signed_string) do
    ActiveSupport::MessageVerifier.new(secret, digest: 'SHA1', serializer: Marshal)
                                  .generate([string_payload, unix_time])
  end

  let(:array_payload) { %w[31ihk2jsCSQNGwARVQwQDVtD K2mF78d9Q8u6MqWHb9CbmfYM].freeze }
  let(:array_payload_encoded) { build_encoded_payload(array_payload, unix_time).freeze }
  let(:array_payload_sig) { '51e14671f012574083c9a16c57df14db2ea14fd5' }
  let(:signed_array) do
    ActiveSupport::MessageVerifier.new(secret, digest: 'SHA1', serializer: Marshal)
                                  .generate([array_payload, unix_time])
  end

  def build_encoded_payload(raw_payload, unix_time)
    Base64.strict_encode64(Marshal.dump([raw_payload, unix_time]))
  end

  it 'has a version number' do
    expect(described_class::VERSION).not_to be nil
  end

  describe 'new' do
    it 'allows blank secret (stored as nil)' do
      described_class.new('').tap do |instance|
        expect(instance.instance_variable_get(:@max_age)).to be(nil)
      end

      described_class.new(nil).tap do |instance|
        expect(instance.instance_variable_get(:@max_age)).to be(nil)
      end
    end

    it 'fails when secret is < 24 bytes' do
      expect {
        described_class.new(secret[0, 23])
      }.to raise_error(described_class::InvalidSecret)
    end
  end

  describe '#generate' do
    subject { described_class.new(secret) }

    it 'takes a string and returns a signed string' do
      allow(_SignedData).to receive(:now_as_unix).and_return(unix_time)
      expect(subject.generate(string_payload)).to eq(signed_string)
    end

    it 'works with an array of strings' do
      allow(_SignedData).to receive(:now_as_unix).and_return(unix_time)
      expect(subject.generate(array_payload)).to eq(signed_array)
    end
  end

  describe '#from_signed_string' do
    subject { described_class.new(secret) }

    context 'without max_age' do
      it 'validates a valid signature of a string payload' do
        expect_signed_data_to_be_valid(subject, signed_string)
      end

      it 'validates a valid signature of an array payload' do
        expect_signed_data_to_be_valid(subject, signed_array)
      end

      it 'fails to validate an invalid signature of string payload' do
        signed_string_with_altered_sig = signed_string[0..-2]
        expect_signed_data_to_be_invalid(subject, signed_string_with_altered_sig)
      end

      it 'fails to validate an invalid signature of array payload' do
        signed_array_with_altered_sig = signed_array[0..-2]
        expect_signed_data_to_be_invalid(subject, signed_array_with_altered_sig)
      end

      it 'fails to validate an altered string payload' do
        altered_string_payload_encoded = build_encoded_payload("#{string_payload}_", unix_time).freeze
        signed_string_with_altered_payload = "#{altered_string_payload_encoded}--#{string_payload_sig}"

        expect_signed_data_to_be_invalid(subject, signed_string_with_altered_payload)
      end

      it 'fails to validate an altered array payload' do
        altered_array_payload_encoded = build_encoded_payload(array_payload + ['_'], unix_time).freeze
        signed_array_with_altered_payload = "#{altered_array_payload_encoded}--#{array_payload_sig}"

        expect_signed_data_to_be_invalid(subject, signed_array_with_altered_payload)
      end
    end

    context 'with max_age' do

      # Callers must define these: max_age, now_unexpired, now_expired
      shared_examples 'a max_age validator' do
        subject { described_class.new(secret, max_age: max_age) }

        context 'string payload' do
          let(:signed_data) { signed_string }

          it 'validates a valid unexpired signature' do
            allow(_SignedData).to receive(:now_as_unix).and_return(now_unexpired)
            expect_signed_data_to_be_valid(subject, signed_data)
          end

          it 'fails to validate an expired signature' do
            allow(_SignedData).to receive(:now_as_unix).and_return(now_expired)
            expect_signed_data_to_be_invalid(subject, signed_data)
          end
        end

        context 'array payload' do
          let(:signed_data) { signed_array }

          it 'validates a valid unexpired signature' do
            allow(_SignedData).to receive(:now_as_unix).and_return(now_unexpired)
            expect_signed_data_to_be_valid(subject, signed_data)
          end

          it 'fails to validate an expired signature' do
            allow(_SignedData).to receive(:now_as_unix).and_return(now_expired)
            expect_signed_data_to_be_invalid(subject, signed_data)
          end
        end
      end

      context 'max_age as integer' do
        let(:max_age) { 7.days.to_i }
        let(:now_unexpired) { unix_time + max_age }
        let(:now_expired) { unix_time + max_age + 1 }
        
        it_behaves_like 'a max_age validator'
      end

      context 'max_age as duration' do
        let(:max_age) { 3.days }
        let(:now_unexpired) { unix_time + max_age.to_i }
        let(:now_expired) { unix_time + max_age.to_i + 1 }

        it_behaves_like 'a max_age validator'
      end
    end
  end

  describe 'instance accessor' do
    around do |ex|
      orig_instance = described_class.instance
      ex.run
      described_class.instance = orig_instance
    end

    context 'initial value' do # backed by NullSigner
      it 'generates a nonsensical signed value without `raise`ing' do
        nonsensical_result = ''
        expect(described_class.instance.generate('hello world')).to eq(nonsensical_result)
      end

      it 'returns an invalid data response without `raise`ing' do
        expect_signed_data_to_be_invalid(described_class.instance, signed_string)
        expect_signed_data_to_be_invalid(described_class.instance, signed_array)
      end
    end

    it 'can store & retrieve an instance' do
      new_instance = described_class.new(secret)
      described_class.instance = new_instance
      expect(described_class.instance).to be(new_instance)
    end
  end
end
