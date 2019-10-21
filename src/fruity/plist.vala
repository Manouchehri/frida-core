namespace Frida.Fruity {
	public class Plist : PlistDict {
		public Plist.from_binary (uint8[] data) throws PlistError {
			var parser = new BinaryParser (this);
			parser.parse (data);
		}

		public Plist.from_xml (string xml) throws PlistError {
			var parser = new XmlParser (this);
			parser.parse (xml);
		}

		public uint8[] to_binary () {
			var output = new MemoryOutputStream.resizable ();

			var writer = new BinaryWriter (output);
			try {
				writer.write_plist (this);

				output.close ();

				uint8[] data = output.steal_data ();
				data.length = (int) output.data_size;
				return data;
			} catch (IOError e) {
				assert_not_reached ();
			}
		}

		public string to_xml () {
			var builder = new StringBuilder ();
			var writer = new XmlWriter (builder);
			writer.write_plist (this);
			return builder.str;
		}

		private class BinaryParser : Object {
			public Plist plist {
				get;
				construct;
			}

			private DataInputStream input;

			private uint8 offset_size;
			private uint8 object_ref_size;
			private uint64 offset_table_offset;

			private uint8 object_info;

			private const uint64 EPOCH = 978307200;

			private const uint64 MAX_OBJECT_SIZE = 100 * 1024 * 1024;
			private const uint64 MAX_OBJECT_COUNT = 32 * 1024;

			public BinaryParser (Plist plist) {
				Object (plist: plist);
			}

			public void parse (uint8[] data) throws PlistError {
				unowned string magic = (string) data;
				if (!magic.has_prefix ("bplist"))
					throw new PlistError.INVALID_DATA ("Invalid binary plist");

				try {
					input = new DataInputStream (new MemoryInputStream.from_bytes (new Bytes.static (data)));
					input.byte_order = BIG_ENDIAN;

					input.seek (-26, END);
					offset_size = input.read_byte ();
					object_ref_size = input.read_byte ();
					var num_objects = input.read_uint64 ();
					if (num_objects > MAX_OBJECT_COUNT)
						throw new PlistError.INVALID_DATA ("Too many objects");
					var top_object_ref = input.read_uint64 ();
					offset_table_offset = input.read_uint64 ();

					var top_object = parse_object (top_object_ref);
					if (!top_object.holds (typeof (PlistDict)))
						throw new PlistError.INVALID_DATA ("Toplevel must be a dict");
					plist.steal_all ((PlistDict) top_object.get_object ());
				} catch (GLib.Error e) {
					throw new PlistError.INVALID_DATA ("Invalid binary plist: %s", e.message);
				}
			}

			private Value? parse_object (uint64 object_ref) throws GLib.Error {
				Value? obj;

				var previous_offset = input.tell ();
				try {
					seek_to_object (object_ref);

					obj = read_value ();
				} catch (GLib.Error e) {
					input.seek (previous_offset, SET);
					throw e;
				}

				input.seek (previous_offset, SET);

				return obj;
			}

			private void seek_to_object (uint64 object_ref) throws GLib.Error {
				input.seek ((int64) (offset_table_offset + (object_ref * offset_size)), SET);
				var offset = read_offset ();
				input.seek ((int64) offset, SET);
			}

			private Value? read_value () throws GLib.Error {
				uint8 marker = input.read_byte ();
				uint8 object_type = (marker & 0xf0) >> 4;
				object_info = marker & 0x0f;

				switch (object_type) {
					case 0x0:
						return read_constant ();
					case 0x1:
						return read_integer ();
					case 0x2:
						return read_real ();
					case 0x3:
						return read_date ();
					case 0x4:
						return read_data ();
					case 0x5:
						return read_ascii_string ();
					case 0x6:
						return read_utf16_string ();
					case 0x8:
						return read_uid ();
					case 0xa:
						return read_array ();
					case 0xd:
						return read_dict ();
					default:
						throw new PlistError.INVALID_DATA ("Unsupported object type: 0x%x", object_type);
				}
			}

			private Value? read_constant () throws GLib.Error {
				Value? gval;

				switch (object_info) {
					case 0x0:
						gval = Value (typeof (PlistNull));
						gval.take_object (new PlistNull ());
						break;
					case 0x8:
					case 0x9:
						gval = Value (typeof (bool));
						gval.set_boolean (object_info == 0x9);
						break;
					default:
						throw new PlistError.INVALID_DATA ("Unsupported constant type: 0x%x", object_info);
				}

				return gval;
			}

			private Value? read_integer () throws GLib.Error {
				if (object_info > 4)
					throw new PlistError.INVALID_DATA ("Integer too large");
				uint size = 1 << object_info;

				int64 val;
				switch (size) {
					case 1:
						val = input.read_byte ();
						break;
					case 2:
						val = input.read_uint16 ();
						break;
					case 4:
						val = input.read_uint32 ();
						break;
					case 8:
						val = input.read_int64 ();
						break;
					default:
						throw new PlistError.INVALID_DATA ("Unsupported integer size: %u", size);
				}

				var gval = Value (typeof (int64));
				gval.set_int64 (val);
				return gval;
			}

			private Value? read_real () throws GLib.Error {
				Value? gval;

				switch (object_info) {
					case 2:
						gval = Value (typeof (float));
						gval.set_float (read_float ());
						break;
					case 3:
						gval = Value (typeof (double));
						gval.set_double (read_double ());
						break;
					default:
						throw new PlistError.INVALID_DATA ("Unsupported number size: %u", 1 << object_info);
				}

				return gval;
			}

			private float read_float () throws GLib.Error {
				uint32 bits = input.read_uint32 ();
				float * val = (float *) &bits;
				return *val;
			}

			private double read_double () throws GLib.Error {
				uint64 bits = input.read_uint64 ();
				double * val = (double *) &bits;
				return *val;
			}

			private Value? read_date () throws GLib.Error {
				double point_in_time = read_double ();

				uint64 seconds = (uint64) point_in_time;
				double remainder = point_in_time - (double) seconds;

				var val = TimeVal ();
				val.tv_sec = (long) (EPOCH + seconds);
				val.tv_usec = (long) (remainder * 1000000.0);

				var gval = Value (typeof (PlistDate));
				gval.take_object (new PlistDate (val));
				return gval;
			}

			private Value? read_data () throws GLib.Error {
				uint64 length = object_info;
				if (object_info == 0xf)
					length = read_length ();
				check_object_size (length);

				var buf = new uint8[length];
				size_t bytes_read;
				input.read_all (buf, out bytes_read);

				var gval = Value (typeof (Bytes));
				gval.take_boxed (new Bytes.take ((owned) buf));
				return gval;
			}

			private Value? read_ascii_string () throws GLib.Error {
				uint64 length = object_info;
				if (object_info == 0xf)
					length = read_length ();
				check_object_size (length);

				var str_buf = new uint8[length + 1];
				str_buf[length] = 0;
				size_t bytes_read;
				input.read_all (str_buf[0:length], out bytes_read);

				unowned string str = (string) str_buf;

				var gval = Value (typeof (string));
				gval.set_string (str);
				return gval;
			}

			private Value? read_utf16_string () throws GLib.Error {
				uint64 length = object_info;
				if (object_info == 0xf)
					length = read_length ();
				uint64 size = length * sizeof (uint16);
				check_object_size (size);

				var str_chars = new uint16[length + 1];
				str_chars[length] = 0;
				unowned uint8[] str_buf = (uint8[]) str_chars;
				size_t bytes_read;
				input.read_all (str_buf[0:size], out bytes_read);

				for (uint64 i = 0; i != length; i++)
					str_chars[i] = uint16.from_big_endian (str_chars[i]);

				unowned string16 str = (string16) str_chars;

				var gval = Value (typeof (string));
				gval.set_string (str.to_utf8 ());
				return gval;
			}

			private Value? read_uid () throws GLib.Error {
				uint64 val = read_uint_of_size (object_info + 1);

				var gval = Value (typeof (PlistUid));
				gval.take_object (new PlistUid (val));
				return gval;
			}

			private Value? read_array () throws GLib.Error {
				uint64 length = object_info;
				if (object_info == 0xf)
					length = read_length ();
				check_object_size (length * object_ref_size);

				var element_refs = new uint64[length];
				for (uint64 i = 0; i != length; i++)
					element_refs[i] = read_ref ();

				var array = new PlistArray ();

				for (uint64 i = 0; i != length; i++) {
					var element = parse_object (element_refs[i]);
					array.add_value (element);
				}

				var gval = Value (typeof (PlistArray));
				gval.set_object (array);
				return gval;
			}

			private Value? read_dict () throws GLib.Error {
				uint64 length = object_info;
				if (object_info == 0xf)
					length = read_length ();
				check_object_size (length * (2 * object_ref_size));

				var key_refs = new uint64[length];
				var val_refs = new uint64[length];
				for (uint64 i = 0; i != length; i++)
					key_refs[i] = read_ref ();
				for (uint64 i = 0; i != length; i++)
					val_refs[i] = read_ref ();

				var dict = new PlistDict ();

				for (uint64 i = 0; i != length; i++) {
					var key = parse_object (key_refs[i]);
					var val = parse_object (val_refs[i]);

					if (!key.holds (typeof (string)))
						throw new PlistError.INVALID_DATA ("Dict keys must be strings, not %s", key.type_name ());

					dict.set_value (key.get_string (), (owned) val);
				}

				var gval = Value (typeof (PlistDict));
				gval.set_object (dict);
				return gval;
			}

			private uint64 read_offset () throws GLib.Error {
				return read_uint_of_size (offset_size);
			}

			private uint64 read_ref () throws GLib.Error {
				return read_uint_of_size (object_ref_size);
			}

			private uint64 read_length () throws GLib.Error {
				var val = read_value ();
				if (!val.holds (typeof (int64)))
					throw new PlistError.INVALID_DATA ("Length must be an integer");

				int64 length = val.get_int64 ();
				if (length < 0)
					throw new PlistError.INVALID_DATA ("Length must be positive");

				return length;
			}

			private uint64 read_uint_of_size (uint size) throws GLib.Error {
				switch (size) {
					case 1:
						return input.read_byte ();
					case 2:
						return input.read_uint16 ();
					case 4:
						return input.read_uint32 ();
					case 8:
						return input.read_uint64 ();
					default:
						throw new PlistError.INVALID_DATA ("Unsupported uint size: %u", size);
				}
			}

			private void check_object_size (uint64 size) throws PlistError {
				if (size > MAX_OBJECT_SIZE)
					throw new PlistError.INVALID_DATA ("Object too large");
			}
		}

		private class BinaryWriter {
			private DataOutputStream output;
			private Gee.HashMap<Value *, Entry> entries = new Gee.HashMap<Value *, Entry> (hash_value, compare_values_eq);
			private Gee.ArrayList<Value *> temporary_values = new Gee.ArrayList<Value *> ();
			private uint next_id = 0;

			public BinaryWriter (OutputStream stream) {
				output = new DataOutputStream (stream);
			}

			~BinaryWriter () {
				temporary_values.foreach (free_value);
			}

			public void write_plist (Plist plist) throws IOError {
				output.put_string ("bplist00");

				var root = make_value (typeof (PlistDict));
				root.set_object (plist);
				temporary_values.add (root);
				collect_value (root);

				printerr ("Have %u entries\n", entries.size);
			}

			private void collect_value (Value * v) {
				Entry? entry = entries[v];
				if (entry == null) {
					entry = new Entry (next_id++);
					entries[v] = entry;
				}

				if (v.holds (typeof (PlistDict))) {
					var dict = (PlistDict) v.get_object ();

					foreach (var key in dict.keys) {
						var k = make_value (typeof (string));
						k.take_string ((owned) key);
						if (!entries.has_key (k)) {
							entries[k] = new Entry (next_id++);
							temporary_values.add (k);
						} else {
							free_value (k);
						}
					}

					foreach (var val in dict.values)
						collect_value (val);

					return;
				}

				if (v.holds (typeof (PlistArray))) {
					var array = (PlistArray) v.get_object ();

					foreach (var val in array.elements)
						collect_value (val);

					return;
				}
			}

			private class Entry {
				public uint id;
				public uint64 offset;

				public Entry (uint id) {
					this.id = id;
					this.offset = 0;
				}
			}
		}

		private class XmlParser : Object {
			public Plist plist {
				get;
				construct;
			}

			private const MarkupParser parser = {
				on_start_element,
				on_end_element,
				on_text,
				null,
				null
			};

			private Gee.Deque<PartialValue> stack = new Gee.LinkedList<PartialValue> ();

			public XmlParser (Plist plist) {
				Object (plist: plist);
			}

			public void parse (string xml) throws PlistError {
				try {
					var context = new MarkupParseContext (parser, 0, this, null);
					context.parse (xml, -1);
				} catch (MarkupError e) {
					throw new PlistError.INVALID_DATA ("%s", e.message);
				}
			}

			private void on_start_element (MarkupParseContext context, string element_name, string[] attribute_names, string[] attribute_values) throws MarkupError {
				var partial = stack.peek_head ();
				if (partial == null) {
					if (element_name == "dict")
						stack.offer_head (new PartialValue.with_dict (plist));
					return;
				}

				switch (partial.need) {
					case DICT_KEY_START:
						if (element_name == "key")
							partial.need = DICT_KEY_TEXT;
						return;
					case DICT_VALUE_START:
						partial.type = element_name;
						partial.val = null;

						if (element_name == "dict") {
							stack.offer_head (new PartialValue.with_dict (new PlistDict ()));
							partial.need = DICT_VALUE_END;
							return;
						}

						if (element_name == "array") {
							stack.offer_head (new PartialValue.with_array (new PlistArray ()));
							partial.need = DICT_VALUE_END;
							return;
						}

						partial.need = DICT_VALUE_TEXT_OR_END;

						return;
					case ARRAY_VALUE_START:
						partial.type = element_name;
						partial.val = null;

						if (element_name == "dict") {
							stack.offer_head (new PartialValue.with_dict (new PlistDict ()));
							partial.need = ARRAY_VALUE_END;
							return;
						}

						if (element_name == "array") {
							stack.offer_head (new PartialValue.with_array (new PlistArray ()));
							partial.need = ARRAY_VALUE_END;
							return;
						}

						partial.need = ARRAY_VALUE_TEXT_OR_END;

						return;
				}
			}

			private void on_end_element (MarkupParseContext context, string element_name) throws MarkupError {
				var partial = stack.peek_head ();
				if (partial == null)
					return;

				switch (partial.need) {
					case DICT_KEY_START:
						if (element_name == "dict") {
							stack.poll_head ();

							var parent = stack.peek_head ();
							if (parent == null)
								return;

							switch (parent.need) {
								case DICT_VALUE_END:
									parent.dict.set_dict (parent.key, partial.dict);
									parent.need = DICT_KEY_START;
									break;
								case ARRAY_VALUE_END:
									parent.array.add_value (partial.dict);
									parent.need = ARRAY_VALUE_START;
									break;
							}
						}

						return;
					case ARRAY_VALUE_START:
						if (element_name == "array") {
							stack.poll_head ();

							var parent = stack.peek_head ();
							if (parent == null)
								return;

							switch (parent.need) {
								case DICT_VALUE_END:
									parent.dict.set_array (parent.key, partial.array);
									parent.need = DICT_KEY_START;
									break;

								case ARRAY_VALUE_END:
									parent.array.add_value (partial.array);
									parent.need = ARRAY_VALUE_START;
									break;
							}
						}

						return;
					case DICT_KEY_END:
						if (element_name == "key")
							partial.need = DICT_VALUE_START;
						return;
					case DICT_VALUE_TEXT_OR_END:
					case DICT_VALUE_END: {
						var val = try_create_value (partial.type, partial.val);
						if (val != null)
							partial.dict.set_value (partial.key, (owned) val);
						partial.need = DICT_KEY_START;
						return;
					}
					case ARRAY_VALUE_TEXT_OR_END:
					case ARRAY_VALUE_END: {
						var val = try_create_value (partial.type, partial.val);
						if (val != null)
							partial.array.add_value (val);
						partial.need = ARRAY_VALUE_START;
						return;
					}
				}
			}

			private void on_text (MarkupParseContext context, string text, size_t text_len) throws MarkupError {
				var partial = stack.peek_head ();
				if (partial == null)
					return;

				switch (partial.need) {
					case DICT_KEY_TEXT:
						partial.key = text;
						partial.need = DICT_KEY_END;
						return;
					case DICT_VALUE_TEXT_OR_END:
						partial.val = text;
						partial.need = DICT_VALUE_END;
						return;
					case ARRAY_VALUE_TEXT_OR_END:
						partial.val = text;
						partial.need = ARRAY_VALUE_END;
						return;
				}
			}

			private class PartialValue {
				public enum Need {
					DICT_KEY_START,
					DICT_KEY_TEXT,
					DICT_KEY_END,
					DICT_VALUE_START,
					DICT_VALUE_TEXT_OR_END,
					DICT_VALUE_END,
					ARRAY_VALUE_START,
					ARRAY_VALUE_TEXT_OR_END,
					ARRAY_VALUE_END
				}

				public PlistDict? dict;
				public PlistArray? array;
				public Need need;
				public string? key;
				public string? type;
				public string? val;

				public PartialValue.with_dict (PlistDict dict) {
					this.dict = dict;
					this.need = DICT_KEY_START;
				}

				public PartialValue.with_array (PlistArray array) {
					this.array = array;
					this.need = ARRAY_VALUE_START;
				}
			}

			public Value? try_create_value (string? type, string? val) {
				Value? result = null;

				if (type == "true") {
					result = Value (typeof (bool));
					result.set_boolean (true);
				} else if (type == "false") {
					result = Value (typeof (bool));
					result.set_boolean (false);
				} else if (type == "integer") {
					result = Value (typeof (int64));
					result.set_int64 (int64.parse (val));
				} else if (type == "string") {
					result = Value (typeof (string));
					result.set_string (val);
				} else if (type == "data") {
					result = Value (typeof (Bytes));
					result.take_boxed (new Bytes.take (Base64.decode (val)));
				}

				return result;
			}
		}

		private class XmlWriter {
			private unowned StringBuilder builder;
			private uint level = 0;

			public XmlWriter (StringBuilder builder) {
				this.builder = builder;
			}

			public void write_plist (Plist plist) {
				write_line ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>");
				write_line ("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">");
				write_line ("<plist version=\"1.0\">");

				write_dict (plist);

				write_line ("</plist>");
			}

			public void write_dict (PlistDict dict) {
				write_line ("<dict>");
				level++;

				var keys = new Gee.ArrayList<string> ();
				foreach (var key in dict.keys)
					keys.add (key);
				keys.sort ();

				foreach (var key in keys) {
					write_tag ("key", key);

					Value * val;
					try {
						val = dict.get_value (key);
					} catch (PlistError e) {
						assert_not_reached ();
					}

					write_value (val);
				}

				level--;
				write_line ("</dict>");
			}

			public void write_array (PlistArray array) {
				write_line ("<array>");
				level++;

				foreach (var val in array.elements)
					write_value (val);

				level--;
				write_line ("</array>");
			}

			public void write_uid (PlistUid val) {
				write_line ("<dict>");
				level++;

				write_tag ("key", "CF$UID");
				write_tag ("integer", val.uid.to_string ());

				level--;
				write_line ("</dict>");
			}

			public void write_value (Value * val) {
				var type = val.type ();
				if (type == typeof (bool)) {
					write_tag (val.get_boolean ().to_string ());
				} else if (type == typeof (int64)) {
					write_tag ("integer", val.get_int64 ().to_string ());
				} else if (type == typeof (string)) {
					write_tag ("string", Markup.escape_text (val.get_string ()));
				} else if (type == typeof (Bytes)) {
					unowned Bytes bytes = (Bytes) val.get_boxed ();
					write_tag ("data", Base64.encode (bytes.get_data ()));
				} else if (type == typeof (PlistDict)) {
					write_dict ((PlistDict) val.get_object ());
				} else if (type == typeof (PlistArray)) {
					write_array ((PlistArray) val.get_object ());
				} else if (type == typeof (PlistUid)) {
					write_uid ((PlistUid) val.get_object ());
				}
			}

			private void write_tag (string name, string? content = null) {
				if (content != null)
					write_line ("<" + name + ">" + content + "</" + name + ">");
				else
					write_line ("<" + name + "/>");
			}

			private void write_line (string line) {
				for (uint i = 0; i != level; i++)
					builder.append_c ('\t');
				builder.append (line);
				builder.append ("\n");
			}
		}
	}

	public class PlistDict : Object {
		public bool is_empty {
			get {
				return storage.is_empty;
			}
		}

		public int size {
			get {
				return storage.size;
			}
		}

		public Gee.Iterable<string> keys {
			owned get {
				return storage.keys;
			}
		}

		public Gee.Iterable<Value *> values {
			owned get {
				return storage.values;
			}
		}

		private Gee.HashMap<string, Value *> storage = new Gee.HashMap<string, Value *> ();

		~PlistDict () {
			storage.values.foreach (free_value);
		}

		public void clear () {
			storage.values.foreach (free_value);
			storage.clear ();
		}

		public void remove (string key) {
			Value * v;
			if (storage.unset (key, out v))
				free_value (v);
		}

		public bool has (string key) {
			return storage.has_key (key);
		}

		public bool get_boolean (string key) throws PlistError {
			return get_value (key, typeof (bool)).get_boolean ();
		}

		public void set_boolean (string key, bool val) {
			var gval = make_value (typeof (bool));
			gval.set_boolean (val);
			set_raw_value (key, gval);
		}

		public int64 get_integer (string key) throws PlistError {
			return get_value (key, typeof (int64)).get_int64 ();
		}

		public void set_integer (string key, int64 val) {
			var gval = make_value (typeof (int64));
			gval.set_int64 (val);
			set_raw_value (key, gval);
		}

		public unowned string get_string (string key) throws PlistError {
			return get_value (key, typeof (string)).get_string ();
		}

		public void set_string (string key, string str) {
			var gval = make_value (typeof (string));
			gval.set_string (str);
			set_raw_value (key, gval);
		}

		public unowned Bytes get_bytes (string key) throws PlistError {
			return (Bytes) get_value (key, typeof (Bytes)).get_boxed ();
		}

		public string get_bytes_as_string (string key) throws PlistError {
			var bytes = get_bytes (key);
			unowned string unterminated_str = (string) bytes.get_data ();
			return unterminated_str[0:bytes.length];
		}

		public void set_bytes (string key, Bytes val) {
			var gval = make_value (typeof (Bytes));
			gval.set_boxed (val);
			set_raw_value (key, gval);
		}

		public unowned PlistDict get_dict (string key) throws PlistError {
			return (PlistDict) get_value (key, typeof (PlistDict)).get_object ();
		}

		public void set_dict (string key, PlistDict dict) {
			var gval = make_value (typeof (PlistDict));
			gval.set_object (dict);
			set_raw_value (key, gval);
		}

		public unowned PlistArray get_array (string key) throws PlistError {
			return (PlistArray) get_value (key, typeof (PlistArray)).get_object ();
		}

		public void set_array (string key, PlistArray array) {
			var gval = make_value (typeof (PlistArray));
			gval.set_object (array);
			set_raw_value (key, gval);
		}

		public unowned PlistUid get_uid (string key) throws PlistError {
			return (PlistUid) get_value (key, typeof (PlistUid)).get_object ();
		}

		public void set_uid (string key, PlistUid uid) {
			var gval = make_value (typeof (PlistUid));
			gval.set_object (uid);
			set_raw_value (key, gval);
		}

		public Value * get_value (string key, GLib.Type expected_type = GLib.Type.INVALID) throws PlistError {
			var val = storage[key];
			if (val == null)
				throw new PlistError.KEY_NOT_FOUND ("Key '%s' does not exist".printf (key));
			if (expected_type != Type.INVALID && !val.holds (expected_type))
				throw new PlistError.TYPE_MISMATCH ("Key '%s' does not have the expected type".printf (key));
			return val;
		}

		public void set_value (string key, owned Value? val) {
			Value * v = null;
			*(void **) &v = (owned) val;
			set_raw_value (key, v);
		}

		public void set_raw_value (string key, Value * val) {
			Value * old_val;
			if (storage.unset (key, out old_val))
				free_value (old_val);

			storage[key] = val;
		}

		public void steal_all (PlistDict dict) {
			storage.set_all (dict.storage);
			dict.storage.clear ();
		}
	}

	public class PlistArray : Object {
		public bool is_empty {
			get {
				return storage.is_empty;
			}
		}

		public int length {
			get {
				return storage.size;
			}
		}

		public Gee.Iterable<Value *> elements {
			get {
				return storage;
			}
		}

		private Gee.ArrayList<Value *> storage = new Gee.ArrayList<Value *> ();

		~PlistArray () {
			storage.foreach (free_value);
		}

		public void clear () {
			storage.foreach (free_value);
			storage.clear ();
		}

		public void remove_at (int index) throws PlistError {
			check_index (index);

			var v = storage[index];
			storage.remove_at (index);
			free_value (v);
		}

		public bool get_boolean (int index) throws PlistError {
			return get_value (index, typeof (bool)).get_boolean ();
		}

		public void add_boolean (bool val) {
			var gval = make_value (typeof (bool));
			gval.set_boolean (val);
			storage.add (gval);
		}

		public int64 get_integer (int index) throws PlistError {
			return get_value (index, typeof (int64)).get_int64 ();
		}

		public void add_integer (int64 val) {
			var gval = make_value (typeof (int64));
			gval.set_int64 (val);
			storage.add (gval);
		}

		public unowned string get_string (int index) throws PlistError {
			return get_value (index, typeof (string)).get_string ();
		}

		public void add_string (string str) {
			var gval = make_value (typeof (string));
			gval.set_string (str);
			storage.add (gval);
		}

		public unowned Bytes get_bytes (int index) throws PlistError {
			return (Bytes) get_value (index, typeof (Bytes)).get_boxed ();
		}

		public string get_bytes_as_string (int index) throws PlistError {
			var bytes = get_bytes (index);
			unowned string unterminated_str = (string) bytes.get_data ();
			return unterminated_str[0:bytes.length];
		}

		public void add_bytes (Bytes val) {
			var gval = make_value (typeof (Bytes));
			gval.set_boxed (val);
			storage.add (gval);
		}

		public unowned PlistDict get_dict (int index) throws PlistError {
			return (PlistDict) get_value (index, typeof (PlistDict)).get_object ();
		}

		public void add_dict (PlistDict dict) {
			var gval = make_value (typeof (PlistDict));
			gval.set_object (dict);
			storage.add (gval);
		}

		public unowned PlistArray get_array (int index) throws PlistError {
			return (PlistArray) get_value (index, typeof (PlistArray)).get_object ();
		}

		public void add_array (PlistArray array) {
			var gval = make_value (typeof (PlistArray));
			gval.set_object (array);
			storage.add (gval);
		}

		public unowned PlistUid get_uid (int index) throws PlistError {
			return (PlistUid) get_value (index, typeof (PlistUid)).get_object ();
		}

		public void add_uid (PlistUid uid) {
			var gval = make_value (typeof (PlistUid));
			gval.set_object (uid);
			storage.add (gval);
		}

		public Value * get_value (int index, GLib.Type expected_type = GLib.Type.INVALID) throws PlistError {
			check_index (index);

			var val = storage[index];
			if (expected_type != Type.INVALID && !val.holds (expected_type))
				throw new PlistError.TYPE_MISMATCH ("Array element does not have the expected type");

			return val;
		}

		public void add_value (owned Value? val) {
			Value * v = null;
			*(void **) &v = (owned) val;
			storage.add (v);
		}

		private void check_index (int index) throws PlistError {
			if (index < 0 || index >= storage.size)
				throw new PlistError.INVALID_INDEX ("Array element does not exist");
		}
	}

	public class PlistNull : Object {
	}

	public class PlistDate : Object {
		private TimeVal time;

		public PlistDate (TimeVal time) {
			this.time = time;
		}

		public TimeVal get_time () {
			return time;
		}
	}

	public class PlistUid : Object {
		public uint64 uid {
			get;
			construct;
		}

		public PlistUid (uint64 uid) {
			Object (uid: uid);
		}
	}

	public errordomain PlistError {
		INVALID_DATA,
		KEY_NOT_FOUND,
		INVALID_INDEX,
		TYPE_MISMATCH
	}

	private static Value * make_value (Type t) {
		Value * v = malloc0 (sizeof (Value));
		v.init (t);
		return v;
	}

	private static bool free_value (Value * v) {
		v.unset ();
		free (v);
		return true;
	}

	private static uint hash_value (Value * v) {
		var t = v.type ();

		if (t == typeof (bool))
			return (uint) t;

		if (t == typeof (int64))
			return (uint) v.get_int64 ();

		if (t == typeof (string))
			return str_hash (v.get_string ());

		if (t == typeof (Bytes) || t == typeof (PlistDict) || t == typeof (PlistArray))
			return (uint) v.get_object ();

		if (t == typeof (PlistUid))
			return (uint) ((PlistUid) v.get_object ()).uid;

		assert_not_reached ();
	}

	private static bool compare_values_eq (Value * a, Value * b) {
		var ta = a.type ();
		var tb = b.type ();
		if (ta != tb)
			return false;
		Type t = ta;

		if (t == typeof (bool))
			return a.get_boolean () == b.get_boolean ();

		if (t == typeof (int64))
			return a.get_int64 () == b.get_int64 ();

		if (t == typeof (string))
			return a.get_string () == b.get_string ();

		if (t == typeof (Bytes) || t == typeof (PlistDict) || t == typeof (PlistArray))
			return a.get_object () == b.get_object ();

		if (t == typeof (PlistUid))
			return ((PlistUid) a.get_object ()).uid == ((PlistUid) b.get_object ()).uid;

		assert_not_reached ();
	}
}
