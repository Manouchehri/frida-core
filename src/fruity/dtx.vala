namespace Frida.Fruity {
	public class DeviceInfoService : Object, AsyncInitable {
		public ChannelProvider channel_provider {
			get;
			construct;
		}

		private DTXChannel channel;

		private DeviceInfoService (ChannelProvider channel_provider) {
			Object (channel_provider: channel_provider);
		}

		public static async DeviceInfoService open (ChannelProvider channel_provider, Cancellable? cancellable = null)
				throws Error, IOError {
			var service = new DeviceInfoService (channel_provider);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_api_error (e);
			}

			return service;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws Error, IOError {
			var connection = yield DTXConnection.obtain (channel_provider, cancellable);

			channel = connection.make_channel ("com.apple.instruments.server.services.deviceinfo");

			return true;
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			yield channel.close (cancellable);
		}

		public async Gee.ArrayList<ProcessInfo> enumerate_running_processes (Cancellable? cancellable = null) throws IOError {
			var result = new Gee.ArrayList<ProcessInfo> ();

			var timeout_source = new TimeoutSource (5000);
			timeout_source.set_callback (enumerate_running_processes.callback);
			timeout_source.attach (MainContext.get_thread_default ());

			yield;

			return result;
		}
	}

	public class ProcessInfo : Object {
		public uint pid {
			get;
			set;
		}

		public string name {
			get;
			set;
		}

		public string real_app_name {
			get;
			set;
		}

		public bool foreground_running {
			get;
			set;
		}

		public DateTime? start_date {
			get;
			set;
		}
	}

	public class DTXConnection : Object {
		public IOStream stream {
			get;
			construct;
		}

		private static Gee.HashMap<ChannelProvider, Future<DTXConnection>> connections;

		private DataInputStream input;
		private OutputStream output;
		private Cancellable io_cancellable = new Cancellable ();

		private Gee.HashMap<uint32, Gee.ArrayList<Fragment>> fragments = new Gee.HashMap<uint32, Gee.ArrayList<Fragment>> ();
		private size_t total_buffered = 0;

		private const uint32 DTX_FRAGMENT_MAGIC = 0x1f3d5b79U;
		private const uint MAX_BUFFERED_COUNT = 100;
		private const size_t MAX_BUFFERED_SIZE = 30 * 1024 * 1024;
		private const size_t MAX_MESSAGE_SIZE = 1024 * 1024;
		private const size_t MAX_FRAGMENT_SIZE = 128 * 1024;

		public static async DTXConnection obtain (ChannelProvider channel_provider, Cancellable? cancellable)
				throws Error, IOError {
			if (connections == null)
				connections = new Gee.HashMap<ChannelProvider, Future<DTXConnection>> ();

			while (connections.has_key (channel_provider)) {
				var future = connections[channel_provider];
				try {
					return yield future.wait_async (cancellable);
				} catch (Error e) {
					throw e;
				} catch (IOError e) {
					cancellable.set_error_if_cancelled ();
				}
			}

			var request = new Promise<DTXConnection> ();
			connections[channel_provider] = request.future;

			try {
				var stream = yield channel_provider.open_channel ("lockdown:com.apple.instruments.remoteserver",
					cancellable);

				var connection = new DTXConnection (stream);

				request.resolve (connection);

				return connection;
			} catch (Error e) {
				request.reject (e);
				connections.unset (channel_provider);

				throw e;
			}
		}

		public DTXConnection (IOStream stream) {
			Object (stream: stream);
		}

		construct {
			input = new DataInputStream (stream.get_input_stream ());
			input.byte_order = LITTLE_ENDIAN;
			output = stream.get_output_stream ();

			process_incoming_fragments.begin ();
		}

		public DTXChannel make_channel (string identifier) {
			return new DTXChannel ();
		}

		private void process_message (uint8[] raw_message, FragmentFlags fragment_flags) throws Error {
			const size_t header_size = 16;

			size_t message_size = raw_message.length;
			if (message_size < header_size)
				throw new Error.PROTOCOL ("Malformed message");

			uint8 * m = (uint8 *) raw_message;

			MessageType type = (MessageType) *m;

			uint32 aux_size = uint32.from_little_endian (*((uint32 *) (m + 4)));
			uint64 data_size = uint64.from_little_endian (*((uint64 *) (m + 8)));
			if (aux_size > message_size || data_size > message_size || data_size != message_size - header_size ||
					aux_size > data_size) {
				throw new Error.PROTOCOL ("Malformed message");
			}

			size_t aux_start_offset = header_size;
			size_t aux_end_offset = aux_start_offset + aux_size;
			unowned uint8[] aux_data = raw_message[aux_start_offset:aux_end_offset];

			size_t payload_start_offset = aux_end_offset;
			size_t payload_end_offset = payload_start_offset + (size_t) (data_size - aux_size);
			unowned uint8[] payload_data = raw_message[payload_start_offset:payload_end_offset];

			printerr ("[process_message] type=%s raw_message.length=%d aux_data.length=%d payload_data.length=%d fragment_flags=%s\n",
				type.to_string (),
				raw_message.length,
				aux_data.length,
				payload_data.length,
				fragment_flags.to_string ());

			if (type == INVOKE) {
				NSString? method_name = NSKeyedArchive.parse (payload_data) as NSString;
				if (method_name == null)
					throw new Error.PROTOCOL ("Malformed message payload");
				printerr ("method_name: %s\n", method_name.str);

				var args = DTXArgumentList.parse (aux_data);
			}
		}

		private async void process_incoming_fragments () {
			while (true) {
				try {
					var fragment = yield read_fragment ();

					if (fragment.count == 1) {
						process_message (fragment.bytes.get_data (), (FragmentFlags) fragment.flags);
						continue;
					}

					Gee.ArrayList<Fragment> entries = fragments[fragment.identifier];
					if (entries == null) {
						if (fragments.size == MAX_BUFFERED_COUNT)
							throw new Error.PROTOCOL ("Total buffered count exceeds maximum");
						if (fragment.index != 0)
							throw new Error.PROTOCOL ("Expected first fragment to have index of zero");
						fragment.data_size = 0;

						entries = new Gee.ArrayList<Fragment> ();
						fragments[fragment.identifier] = entries;
					}
					entries.add (fragment);

					var first_fragment = entries[0];

					if (fragment.bytes != null) {
						var size = fragment.bytes.get_size ();

						first_fragment.data_size += (uint32) size;
						if (first_fragment.data_size > MAX_MESSAGE_SIZE)
							throw new Error.PROTOCOL ("Message size exceeds maximum");

						total_buffered += size;
						if (total_buffered > MAX_BUFFERED_SIZE)
							throw new Error.PROTOCOL ("Total buffered size exceeds maximum");
					}

					if (entries.size == fragment.count) {
						var message = new uint8[first_fragment.data_size];

						var sorted_entries = entries.order_by ((a, b) => (int) a.index - (int) b.index);
						uint i = 0;
						size_t offset = 0;
						while (sorted_entries.next ()) {
							Fragment f = sorted_entries.get ();

							if (f.index != i)
								throw new Error.PROTOCOL ("Inconsistent fragments received");

							var bytes = f.bytes;
							if (bytes != null) {
								var size = bytes.get_size ();
								Memory.copy ((uint8 *) message + offset, (uint8 *) bytes.get_data (), size);
								offset += size;
							}

							i++;
						}

						fragments.unset (fragment.identifier);
						total_buffered -= message.length;

						process_message (message, (FragmentFlags) first_fragment.flags);
					}
				} catch (GLib.Error e) {
					printerr ("DERP: %s\n", e.message);
					return;
				}
			}
		}

		private async Fragment read_fragment () throws Error, IOError {
			var io_priority = Priority.DEFAULT;

			try {
				size_t minimum_header_size = 32;

				yield prepare_to_read (minimum_header_size);

				uint32 magic = input.read_uint32 (io_cancellable);
				if (magic != DTX_FRAGMENT_MAGIC)
					throw new Error.PROTOCOL ("Expected DTX message magic, got 0x%08x", magic);

				var fragment = new Fragment ();

				var header_size = input.read_uint32 (io_cancellable);
				if (header_size < minimum_header_size)
					throw new Error.PROTOCOL ("Expected header size of >= 32, got %u", header_size);

				fragment.index = input.read_uint16 (io_cancellable);
				fragment.count = input.read_uint16 (io_cancellable);
				fragment.data_size = input.read_uint32 (io_cancellable);
				fragment.identifier = input.read_uint32 (io_cancellable);
				fragment.conversation_index = input.read_uint32 (io_cancellable);
				fragment.channel_code = input.read_uint32 (io_cancellable);
				fragment.flags = input.read_uint32 (io_cancellable);

				size_t extra_header_size = header_size - minimum_header_size;
				if (extra_header_size > 0)
					yield input.skip_async (extra_header_size, io_priority, io_cancellable);

				if (fragment.count == 1 || fragment.index != 0) {
					if (fragment.data_size == 0)
						throw new Error.PROTOCOL ("Empty fragments are not allowed");
					if (fragment.data_size > MAX_FRAGMENT_SIZE)
						throw new Error.PROTOCOL ("Fragment size exceeds maximum");

					if (fragment.data_size > input.get_buffer_size ())
						input.set_buffer_size (fragment.data_size);

					yield prepare_to_read (fragment.data_size);
					fragment.bytes = input.read_bytes (fragment.data_size, io_cancellable);
				}

				return fragment;
			} catch (GLib.Error e) {
				if (e is Error)
					throw (Error) e;
				throw new Error.TRANSPORT ("%s", e.message);
			}
		}

		private async void prepare_to_read (size_t required) throws GLib.Error {
			while (true) {
				size_t available = input.get_available ();
				if (available >= required)
					return;
				ssize_t n = yield input.fill_async ((ssize_t) (required - available), Priority.DEFAULT, io_cancellable);
				if (n == 0)
					throw new Error.TRANSPORT ("Connection closed");
			}
		}

		private enum MessageType {
			OK = 0,
			INVOKE = 2,
			RESULT = 3,
			ERROR = 4,
			BARRIER = 5
		}

		private class Fragment {
			public uint16 index;
			public uint16 count;
			public uint32 data_size;
			public uint32 identifier;
			public uint32 conversation_index;
			public uint32 channel_code;
			public uint32 flags;
			public Bytes? bytes;
		}

		[Flags]
		private enum FragmentFlags {
			EXPECTS_REPLY = (1 << 0),
		}
	}

	public class DTXChannel : Object {
		public async void close (Cancellable? cancellable = null) throws IOError {
		}
	}

	private class DTXArgumentList {
		private Value[] elements;

		private DTXArgumentList (owned Value[] elements) {
			this.elements = (owned) elements;
		}

		public static DTXArgumentList parse (uint8[] data) throws Error {
			var elements = new Value[0];

			var reader = new PrimitiveReader (data);

			reader.skip (16);

			while (reader.available_bytes != 0) {
				PrimitiveType type;

				type = (PrimitiveType) reader.read_uint32 ();
				if (type != INDEX)
					throw new Error.PROTOCOL ("Unsupported primitive dictionary");

				type = (PrimitiveType) reader.read_uint32 ();
				switch (type) {
					case STRING: {
						size_t size = reader.read_uint32 ();
						string str = reader.read_string (size);

						var gval = Value (typeof (string));
						gval.take_string ((owned) str);
						elements += (owned) gval;

						break;
					}
					case BUFFER: {
						size_t size = reader.read_uint32 ();
						unowned uint8[] buf = reader.read_byte_array (size);

						NSObject? obj = NSKeyedArchive.parse (buf);
						if (obj != null) {
							var gval = Value (Type.from_instance (obj));
							gval.set_instance (obj);
							elements += (owned) gval;
						} else {
							var gval = Value (typeof (NSObject));
							elements += (owned) gval;
						}

						break;
					}
					case INT32: {
						int32 val = reader.read_int32 ();

						var gval = Value (typeof (int));
						gval.set_int (val);
						elements += (owned) gval;

						break;
					}
					case INT64: {
						int64 val = reader.read_int64 ();

						var gval = Value (typeof (int64));
						gval.set_int64 (val);
						elements += (owned) gval;

						break;
					}
					case DOUBLE: {
						double val = reader.read_double ();

						var gval = Value (typeof (double));
						gval.set_double (val);
						elements += (owned) gval;

						break;
					}
					default:
						throw new Error.PROTOCOL ("Unsupported primitive dictionary");
				}
			}

			return new DTXArgumentList ((owned) elements);
		}
	}

	private class NSObject {
	}

	private class NSString : NSObject {
		public string str {
			get;
			private set;
		}

		public NSString (string str) {
			this.str = str;
		}

		public static uint hash (NSString val) {
			return str_hash (val.str);
		}

		public bool equal (NSString a, NSString b) {
			return str_equal (a.str, b.str);
		}
	}

	private class NSDictionary : NSObject {
		public int size {
			get {
				return storage.size;
			}
		}

		public Gee.Iterable<NSObject> keys {
			owned get {
				return storage.keys;
			}
		}

		public Gee.Iterable<NSObject> values {
			owned get {
				return storage.values;
			}
		}

		private Gee.HashMap<NSObject, NSObject> storage;

		public NSDictionary (Gee.HashMap<NSObject, NSObject> storage) {
			this.storage = storage;
		}
	}

	namespace NSKeyedArchive {
		private Gee.HashMap<string, DecodeFunc> decoders;

		[CCode (has_target = false)]
		private delegate NSObject DecodeFunc (PlistDict instance, PlistArray objects) throws Error, PlistError;

		private static NSObject? parse (uint8[] data) throws Error {
			ensure_decoders_registered ();

			try {
				var plist = new Plist.from_binary (data);

				printerr ("parse: %s\n", plist.to_xml ());
				FileUtils.set_data ("/Users/oleavr/VMShared/nskeyedarchive.plist", data);

				return decode_value (plist.get_dict ("$top").get_uid ("root"), plist.get_array ("$objects"));
			} catch (PlistError e) {
				throw new Error.PROTOCOL ("%s", e.message);
			}
		}

		private static NSObject? decode_value (PlistUid index, PlistArray objects) throws Error, PlistError {
			var uid = index.uid;
			if (uid == 0)
				return null;

			Value val = objects.get_value ((int) uid);
			Type t = val.type ();

			if (t == typeof (string))
				return new NSString (val.get_string ());

			if (t == typeof (PlistDict)) {
				var instance = val.get_object () as PlistDict;
				var klass = objects.get_dict ((int) instance.get_uid ("$class").uid);
				var decode = get_decoder (klass);
				return decode (instance, objects);
			}

			throw new Error.PROTOCOL ("Unsupported NSKeyedArchive type: %s", val.type_name ());
		}

		private static DecodeFunc get_decoder (PlistDict klass) throws Error, PlistError {
			var hierarchy = klass.get_array ("$classes");

			int n = hierarchy.length;
			for (int i = 0; i != n; i++) {
				var name = hierarchy.get_string (i);
				var decoder = decoders[name];
				if (decoder != null)
					return decoder;
			}

			throw new Error.PROTOCOL ("No decoder for NSKeyedArchive type “%s”", klass.get_string ("$classname"));
		}

		private static void ensure_decoders_registered () {
			if (decoders != null)
				return;

			decoders = new Gee.HashMap<string, DecodeFunc> ();
			decoders["NSDictionary"] = decode_dictionary;
		}

		private static NSObject decode_dictionary (PlistDict instance, PlistArray objects) throws Error, PlistError {
			var keys = instance.get_array ("NS.keys");
			var objs = instance.get_array ("NS.objects");

			Gee.HashMap<NSObject, NSObject> storage = null;

			var n = keys.length;
			for (int i = 0; i != n; i++) {
				var key = decode_value (keys.get_uid (i), objects);
				var obj = decode_value (objs.get_uid (i), objects);

				if (storage == null) {
					Gee.HashDataFunc<NSObject> key_hash = null;
					Gee.EqualDataFunc<NSObject> key_equal = null;

					if (key is NSString) {
						key_hash = (Gee.HashDataFunc<NSObject>) NSString.hash;
						key_equal = (Gee.EqualDataFunc<NSObject>) NSString.equal;
					}

					storage = new Gee.HashMap<NSObject, NSObject> ((owned) key_hash, (owned) key_equal);
				}

				storage[key] = obj;
			}

			if (storage == null)
				storage = new Gee.HashMap<NSObject, NSObject> ();

			return new NSDictionary (storage);
		}
	}

	private enum PrimitiveType {
		STRING = 1,
		BUFFER = 2,
		INT32 = 3,
		INT64 = 6,
		DOUBLE = 9,
		INDEX = 10
	}

	private class PrimitiveReader {
		public size_t available_bytes {
			get {
				return end - cursor;
			}
		}

		private uint8 * cursor;
		private uint8 * end;

		public PrimitiveReader (uint8[] data) {
			cursor = (uint8 *) data;
			end = cursor + data.length;
		}

		public void skip (size_t n) throws Error {
			check_available (n);
			cursor += n;
		}

		public int32 read_int32 () throws Error {
			const size_t n = sizeof (int32);
			check_available (n);

			int32 val = int32.from_little_endian (*((int32 *) cursor));
			cursor += n;

			return val;
		}

		public uint32 read_uint32 () throws Error {
			const size_t n = sizeof (uint32);
			check_available (n);

			uint32 val = uint32.from_little_endian (*((uint32 *) cursor));
			cursor += n;

			return val;
		}

		public int64 read_int64 () throws Error {
			const size_t n = sizeof (int64);
			check_available (n);

			int64 val = int64.from_little_endian (*((int64 *) cursor));
			cursor += n;

			return val;
		}

		public double read_double () throws Error {
			int64 val = read_int64 ();
			double * d = (double *) &val;
			return *d;
		}

		public unowned uint8[] read_byte_array (size_t n) throws Error {
			check_available (n);

			return ((uint8[]) cursor)[0:n];
		}

		public string read_string (size_t size) throws Error {
			check_available (size);

			unowned string data = (string) cursor;
			string str = data.substring (0, (long) size);
			cursor += size;

			return str;
		}

		private void check_available (size_t n) throws Error {
			if (cursor + n > end)
				throw new Error.PROTOCOL ("Invalid dictionary");
		}
	}
}
