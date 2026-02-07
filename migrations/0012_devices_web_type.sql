ALTER TABLE devices DROP CONSTRAINT devices_type_check;
ALTER TABLE devices
  ADD CONSTRAINT devices_type_check CHECK (type IN ('mobile','hardware','email','sms','web'));
