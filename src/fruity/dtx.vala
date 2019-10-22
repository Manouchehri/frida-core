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

		public async Gee.ArrayList<ProcessInfo> enumerate_running_processes (Cancellable? cancellable = null)
				throws Error, IOError {
			var result = new Gee.ArrayList<ProcessInfo> ();

			var response = yield channel.invoke ("runningProcesses", null, cancellable);

			NSArray? processes = response as NSArray;
			if (processes == null)
				throw new Error.PROTOCOL ("Malformed response");

			printerr ("Got %u processes\n", processes.length);

			var start_date_key = new NSString ("startDate");

			foreach (var element in processes.elements) {
				NSDictionary? process = element as NSDictionary;
				if (process == null)
					throw new Error.PROTOCOL ("Malformed response");

				var info = new ProcessInfo ();

				info.pid = (uint) process.get_integer ("pid");

				info.name = process.get_string ("name");
				info.real_app_name = process.get_string ("realAppName");

				bool foreground_running;
				if (process.get_optional_boolean ("foregroundRunning", out foreground_running))
					info.foreground_running = foreground_running;

				// info.start_date = process.get_date ("startDate");

				printerr ("name: \"%s\" pid=%u\n", info.name, info.pid);

				result.add (info);
			}

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

	private class DTXConnection : Object, DTXTransport {
		public IOStream stream {
			get;
			construct;
		}

		private static Gee.HashMap<ChannelProvider, Future<DTXConnection>> connections;

		private DataInputStream input;
		private OutputStream output;
		private Cancellable io_cancellable = new Cancellable ();

		private Gee.HashMap<uint32, Gee.ArrayList<Fragment>> fragments = new Gee.HashMap<uint32, Gee.ArrayList<Fragment>> ();
		private uint32 next_fragment_identifier = 1;
		private size_t total_buffered = 0;
		private Gee.ArrayQueue<Bytes> pending_writes = new Gee.ArrayQueue<Bytes> ();

		private Gee.HashMap<uint32, DTXChannel> channels = new Gee.HashMap<uint32, DTXChannel> ();
		private int32 next_channel_code = 1;

		private const uint32 DTX_FRAGMENT_MAGIC = 0x1f3d5b79U;
		private const uint MAX_BUFFERED_COUNT = 100;
		private const size_t MAX_BUFFERED_SIZE = 30 * 1024 * 1024;
		private const size_t MAX_MESSAGE_SIZE = 1024 * 1024;
		private const size_t MAX_FRAGMENT_SIZE = 128 * 1024;

		private const int32 CONTROL_CHANNEL_CODE = 0;

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

			var control_channel = new DTXChannel (CONTROL_CHANNEL_CODE, this);
			channels[CONTROL_CHANNEL_CODE] = control_channel;

			send_capabilities ();

			process_incoming_fragments.begin ();
		}

		public DTXChannel make_channel (string identifier) {
			int32 channel_code = next_channel_code++;

			var channel = new DTXChannel (channel_code, this);
			channels[channel_code] = channel;

			request_channel.begin (channel, identifier);

			return channel;
		}

		private void send_capabilities () {
			var control_channel = channels[CONTROL_CHANNEL_CODE];

			var capabilities = new NSDictionary ();
			capabilities.set_integer ("com.apple.private.DTXConnection", 1);
			capabilities.set_integer ("com.apple.private.DTXBlockCompression", 2);

			var args = new DTXArgumentListBuilder ()
				.append_object (capabilities);
			control_channel.invoke_without_reply ("_notifyOfPublishedCapabilities:", args);
		}

		private async void request_channel (DTXChannel channel, string identifier) {
			var control_channel = channels[CONTROL_CHANNEL_CODE];

			var args = new DTXArgumentListBuilder ()
				.append_int32 (channel.code)
				.append_object (new NSString (identifier));
			try {
				yield control_channel.invoke ("_requestChannelWithCode:identifier:", args, io_cancellable);
				printerr ("w00t!\n");
			} catch (GLib.Error e) {
				printerr ("Oopsie: %s\n", e.message);
				channels.unset (channel.code);
			}
		}

		private async void process_incoming_fragments () {
			while (true) {
				try {
					var fragment = yield read_fragment ();

					if (fragment.count == 1) {
						process_message (fragment.bytes.get_data (), fragment);
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

						process_message (message, first_fragment);
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
				fragment.channel_code = input.read_int32 (io_cancellable);
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

		private void process_message (uint8[] raw_message, Fragment fragment) throws Error {
			const size_t header_size = 16;

			size_t message_size = raw_message.length;
			if (message_size < header_size)
				throw new Error.PROTOCOL ("Malformed message");

			uint8 * m = (uint8 *) raw_message;

			var message = DTXMessage ();
			message.type = (DTXMessageType) *m;
			message.identifier = fragment.identifier;
			message.conversation_index = fragment.conversation_index;
			message.channel_code = fragment.channel_code;
			message.transport_flags = (DTXMessageTransportFlags) fragment.flags;

			uint32 aux_size = uint32.from_little_endian (*((uint32 *) (m + 4)));
			uint64 data_size = uint64.from_little_endian (*((uint64 *) (m + 8)));
			if (aux_size > message_size || data_size > message_size || data_size != message_size - header_size ||
					aux_size > data_size) {
				throw new Error.PROTOCOL ("Malformed message");
			}

			size_t aux_start_offset = header_size;
			size_t aux_end_offset = aux_start_offset + aux_size;
			message.aux_data = raw_message[aux_start_offset:aux_end_offset];

			size_t payload_start_offset = aux_end_offset;
			size_t payload_end_offset = payload_start_offset + (size_t) (data_size - aux_size);
			message.payload_data = raw_message[payload_start_offset:payload_end_offset];

			int32 channel_code = message.channel_code;
			bool is_notification = false;
			if (message.type == RESULT && channel_code < 0) {
				channel_code = -channel_code;
				is_notification = true;
			}

			var channel = channels[channel_code];
			if (channel == null) {
				printerr ("Got a message for an unknown channel with channel_code=%d\n", message.channel_code);
				return;
			}

			switch (message.type) {
				case INVOKE:
					channel.handle_invoke (message);
					break;
				case OK:
				case RESULT:
				case ERROR:
					if (is_notification)
						channel.handle_notification (message);
					else
						channel.handle_response (message);
					break;
				case BARRIER:
					channel.handle_barrier (message);
					break;
			}
		}

		private void send_message (DTXMessage message, out uint32 identifier) {
			const size_t message_header_size = 16;
			uint32 message_aux_size = message.aux_data.length;
			uint64 message_data_size = message_aux_size + message.payload_data.length;
			size_t message_size = message_header_size + (size_t) message_data_size;
			const uint8 message_flags_a = 0;
			const uint8 message_flags_b = 0;
			const uint8 message_reserved = 0;

			const uint32 fragment_header_size = 32;
			const uint16 fragment_index = 0;
			const uint16 fragment_count = 1;
			uint32 fragment_data_size = (uint32) message_size;
			uint32 fragment_identifier = message.identifier;
			if (fragment_identifier == 0)
				fragment_identifier = next_fragment_identifier++;
			uint32 fragment_flags = message.transport_flags;

			var data = new uint8[fragment_header_size + message_size];

			uint8 * p = (uint8 *) data;
			*((uint32 *) (p + 0)) = DTX_FRAGMENT_MAGIC.to_little_endian ();
			*((uint32 *) (p + 4)) = fragment_header_size.to_little_endian ();
			*((uint16 *) (p + 8)) = fragment_index.to_little_endian ();
			*((uint16 *) (p + 10)) = fragment_count.to_little_endian ();
			*((uint32 *) (p + 12)) = fragment_data_size.to_little_endian ();
			*((uint32 *) (p + 16)) = fragment_identifier.to_little_endian ();
			*((uint32 *) (p + 20)) = message.conversation_index.to_little_endian ();
			*((int32 *) (p + 24)) = message.channel_code.to_little_endian ();
			*((uint32 *) (p + 28)) = fragment_flags.to_little_endian ();
			p += fragment_header_size;

			*(p + 0) = message.type;
			*(p + 1) = message_flags_a;
			*(p + 2) = message_flags_b;
			*(p + 3) = message_reserved;
			*((uint32 *) (p + 4)) = message_aux_size.to_little_endian ();
			*((uint64 *) (p + 8)) = message_data_size.to_little_endian ();
			p += message_header_size;

			Memory.copy (p, message.aux_data, message.aux_data.length);
			p += message.aux_data.length;

			Memory.copy (p, message.payload_data, message.payload_data.length);
			p += message.payload_data.length;

			assert (p == (uint8 *) data + data.length);

			write_bytes (new Bytes.take ((owned) data));

			identifier = fragment_identifier;
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

		private void write_bytes (Bytes bytes) {
			pending_writes.offer_tail (bytes);
			if (pending_writes.size == 1)
				process_pending_writes.begin ();
		}

		private async void process_pending_writes () {
			while (!pending_writes.is_empty) {
				Bytes current = pending_writes.peek_head ();

				size_t bytes_written;
				try {
					yield output.write_all_async (current.get_data (), Priority.DEFAULT, io_cancellable,
						out bytes_written);
				} catch (GLib.Error e) {
					return;
				}

				pending_writes.poll_head ();
			}
		}

		private class Fragment {
			public uint16 index;
			public uint16 count;
			public uint32 data_size;
			public uint32 identifier;
			public uint32 conversation_index;
			public int32 channel_code;
			public uint32 flags;
			public Bytes? bytes;
		}
	}

	private class DTXChannel : Object {
		public signal void notification (NSDictionary dict);
		public signal void barrier ();

		public int32 code {
			get;
			construct;
		}

		public weak DTXTransport transport {
			get;
			construct;
		}

		private Gee.HashMap<uint32, Promise<NSObject?>> pending_responses = new Gee.HashMap<uint32, Promise<NSObject?>> ();

		public DTXChannel (int32 code, DTXTransport transport) {
			Object (code: code, transport: transport);
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
		}

		public async NSObject? invoke (string method_name, DTXArgumentListBuilder? args, Cancellable? cancellable)
				throws Error, IOError {
			var message = DTXMessage ();
			message.type = INVOKE;
			message.channel_code = code;
			message.transport_flags = EXPECTS_REPLY;

			Bytes aux_data;
			if (args != null) {
				aux_data = args.build ();
				message.aux_data = aux_data.get_data ();
			}

			var payload_data = NSKeyedArchive.encode (new NSString (method_name));
			message.payload_data = payload_data;

			uint32 identifier;
			transport.send_message (message, out identifier);
			printerr ("[DTXChannel %d] invoke() %s, identifier=%u\n", code, method_name, identifier);

			var request = new Promise<NSObject?> ();
			pending_responses[identifier] = request;

			try {
				return yield request.future.wait_async (cancellable);
			} finally {
				pending_responses.unset (identifier);
			}
		}

		public void invoke_without_reply (string method_name, DTXArgumentListBuilder? args) {
			var message = DTXMessage ();
			message.type = INVOKE;
			message.channel_code = code;
			message.transport_flags = NONE;

			Bytes aux_data;
			if (args != null) {
				aux_data = args.build ();
				message.aux_data = aux_data.get_data ();
			}

			var payload_data = NSKeyedArchive.encode (new NSString (method_name));
			message.payload_data = payload_data;

			uint32 identifier;
			transport.send_message (message, out identifier);
			printerr ("[DTXChannel %d] invoke_without_reply() %s\n", code, method_name);
		}

		internal void handle_invoke (DTXMessage message) throws Error {
			NSString? method_name = NSKeyedArchive.decode (message.payload_data) as NSString;
			if (method_name == null)
				throw new Error.PROTOCOL ("Malformed invocation payload");

			printerr ("[DTXChannel %d] INVOKE: %s\n", code, method_name.str);

			// var args = DTXArgumentList.parse (message.aux_data);
		}

		internal void handle_response (DTXMessage message) throws Error {
			printerr ("[DTXChannel %d] RESPONSE type=%s identifier=%u\n", code, message.type.to_string (), message.identifier);

			var request = pending_responses[message.identifier];
			if (request != null) {
				switch (message.type) {
					case OK:
						request.resolve (null);
						break;
					case RESULT:
						request.resolve (NSKeyedArchive.decode (message.payload_data));
						break;
					case ERROR: {
						NSError? error = NSKeyedArchive.decode (message.payload_data) as NSError;
						if (error == null)
							throw new Error.PROTOCOL ("Malformed error payload");

						var description = new StringBuilder.sized (128);

						var user_info = error.user_info;
						if (user_info != null) {
							string str;
							if (user_info.get_optional_string ("NSLocalizedDescription", out str))
								description.append (str);
						}

						if (description.len == 0) {
							description.append_printf ("Invocation failed; domain=%s code=%" +
									int64.FORMAT_MODIFIER + "d",
								error.domain.str, error.code);
						}

						request.reject (new Error.NOT_SUPPORTED ("%s", description.str));

						break;
					}
				}
			}
		}

		internal void handle_notification (DTXMessage message) throws Error {
			printerr ("[DTXChannel %d] NOTIFICATION\n", code);
			NSDictionary? dict = NSKeyedArchive.decode (message.payload_data) as NSDictionary;
			if (dict == null)
				throw new Error.PROTOCOL ("Malformed notification payload");
			notification (dict);
		}

		internal void handle_barrier (DTXMessage message) throws Error {
			printerr ("[DTXChannel %d] BARRIER\n", code);
			barrier ();
		}
	}

	private interface DTXTransport : Object {
		public abstract void send_message (DTXMessage message, out uint32 identifier);
	}

	private enum DTXMessageType {
		OK = 0,
		INVOKE = 2,
		RESULT = 3,
		ERROR = 4,
		BARRIER = 5
	}

	private struct DTXMessage {
		public DTXMessageType type;
		public uint32 identifier;
		public uint32 conversation_index;
		public int32 channel_code;
		public DTXMessageTransportFlags transport_flags;
		public unowned uint8[] aux_data;
		public unowned uint8[] payload_data;
	}

	[Flags]
	public enum DTXMessageTransportFlags {
		NONE          = 0,
		EXPECTS_REPLY = (1 << 0),
	}

	private class DTXArgumentList {
		private Value[] elements;

		private DTXArgumentList (owned Value[] elements) {
			this.elements = (owned) elements;
		}

		public static DTXArgumentList parse (uint8[] data) throws Error {
			var elements = new Value[0];

			var reader = new PrimitiveReader (data);

			reader.skip (PRIMITIVE_DICTIONARY_HEADER_SIZE);

			while (reader.available_bytes != 0) {
				PrimitiveType type;

				type = (PrimitiveType) reader.read_uint32 ();
				if (type != INDEX)
					throw new Error.PROTOCOL ("Unsupported primitive dictionary key type");

				type = (PrimitiveType) reader.read_uint32 ();
				switch (type) {
					case STRING: {
						size_t size = reader.read_uint32 ();
						string val = reader.read_string (size);

						var gval = Value (typeof (string));
						gval.take_string ((owned) val);
						elements += (owned) gval;

						break;
					}
					case BUFFER: {
						size_t size = reader.read_uint32 ();
						unowned uint8[] buf = reader.read_byte_array (size);

						NSObject? obj = NSKeyedArchive.decode (buf);
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
						throw new Error.PROTOCOL ("Unsupported primitive dictionary value type");
				}
			}

			return new DTXArgumentList ((owned) elements);
		}
	}

	private class DTXArgumentListBuilder {
		private PrimitiveBuilder blob = new PrimitiveBuilder ();

		public DTXArgumentListBuilder () {
			blob.seek (PRIMITIVE_DICTIONARY_HEADER_SIZE);
		}

		public unowned DTXArgumentListBuilder append_string (string str) {
			begin_entry (STRING)
				.append_uint32 (str.length)
				.append_string (str);
			return this;
		}

		public unowned DTXArgumentListBuilder append_object (NSObject? obj) {
			var buf = NSKeyedArchive.encode (obj);
			begin_entry (BUFFER)
				.append_uint32 (buf.length)
				.append_byte_array (buf);
			return this;
		}

		public unowned DTXArgumentListBuilder append_int32 (int32 val) {
			begin_entry (INT32)
				.append_int32 (val);
			return this;
		}

		public unowned DTXArgumentListBuilder append_int64 (int64 val) {
			begin_entry (INT64)
				.append_int64 (val);
			return this;
		}

		public unowned DTXArgumentListBuilder append_double (double val) {
			begin_entry (DOUBLE)
				.append_double (val);
			return this;
		}

		private unowned PrimitiveBuilder begin_entry (PrimitiveType type) {
			return blob
				.append_uint32 (PrimitiveType.INDEX)
				.append_uint32 (type);
		}

		public Bytes build () {
			size_t size = blob.offset - PRIMITIVE_DICTIONARY_HEADER_SIZE;
			return blob.seek (0)
				.append_uint64 (size)
				.append_uint64 (size)
				.build ();
		}
	}

	private class NSObject {
		public virtual uint hash () {
			return (uint) this;
		}

		public virtual bool is_equal_to (NSObject other) {
			return other == this;
		}

		public virtual string to_string () {
			return "NSObject";
		}

		public static uint hash_func (NSObject val) {
			return val.hash ();
		}

		public static bool equal_func (NSObject a, NSObject b) {
			return a.is_equal_to (b);
		}
	}

	private class NSNumber : NSObject {
		public bool boolean {
			get;
			private set;
		}

		public int64 integer {
			get;
			private set;
		}

		public NSNumber.from_boolean (bool val) {
			boolean = val;
			integer = val ? 1 : 0;
		}

		public NSNumber.from_integer (int64 val) {
			boolean = (val != 0) ? true : false;
			integer = val;
		}

		public override uint hash () {
			return (uint) integer;
		}

		public override bool is_equal_to (NSObject other) {
			var other_number = other as NSNumber;
			if (other_number == null)
				return false;
			return other_number.integer == integer;
		}

		public override string to_string () {
			return integer.to_string ();
		}
	}

	private class NSString : NSObject {
		public string str {
			get;
			private set;
		}

		public NSString (string str) {
			this.str = str;
		}

		public override uint hash () {
			return str.hash ();
		}

		public override bool is_equal_to (NSObject other) {
			var other_string = other as NSString;
			if (other_string == null)
				return false;
			return other_string.str == str;
		}

		public override string to_string () {
			return str;
		}
	}

	private class NSDictionary : NSObject {
		public int size {
			get {
				return storage.size;
			}
		}

		public Gee.Set<Gee.Map.Entry<string, NSObject>> entries {
			owned get {
				return storage.entries;
			}
		}

		public Gee.Iterable<string> keys {
			owned get {
				return storage.keys;
			}
		}

		public Gee.Iterable<NSObject> values {
			owned get {
				return storage.values;
			}
		}

		private Gee.HashMap<string, NSObject> storage;

		public NSDictionary (Gee.HashMap<string, NSObject>? storage = null) {
			this.storage = (storage != null) ? storage : new Gee.HashMap<string, NSObject> ();
		}

		public bool get_boolean (string key) throws Error {
			bool val;
			if (!get_optional_boolean (key, out val))
				throw new Error.PROTOCOL ("Expected dictionary to contain “%s”", key);
			return val;
		}

		public bool get_optional_boolean (string key, out bool val) throws Error {
			val = false;

			NSObject? opaque_obj = storage[key];
			if (opaque_obj == null)
				return false;

			NSNumber? number_obj = opaque_obj as NSNumber;
			if (number_obj == null) {
				throw new Error.PROTOCOL ("Expected “%s” to be a number but got “%s”",
					key.to_string (), Type.from_instance (opaque_obj).name ());
			}

			val = number_obj.boolean;
			return true;
		}

		public int64 get_integer (string key) throws Error {
			int64 val;
			if (!get_optional_integer (key, out val))
				throw new Error.PROTOCOL ("Expected dictionary to contain “%s”", key);
			return val;
		}

		public bool get_optional_integer (string key, out int64 val) throws Error {
			val = -1;

			NSObject? opaque_obj = storage[key];
			if (opaque_obj == null)
				return false;

			NSNumber? number_obj = opaque_obj as NSNumber;
			if (number_obj == null) {
				throw new Error.PROTOCOL ("Expected “%s” to be a number but got “%s”",
					key.to_string (), Type.from_instance (opaque_obj).name ());
			}

			val = number_obj.integer;
			return true;
		}

		public void set_integer (string key, int64 val) {
			storage[key] = new NSNumber.from_integer (val);
		}

		public unowned string get_string (string key) throws Error {
			unowned string val;
			if (!get_optional_string (key, out val))
				throw new Error.PROTOCOL ("Expected dictionary to contain “%s”", key);
			return val;
		}

		public bool get_optional_string (string key, out unowned string? val) throws Error {
			val = null;

			NSObject? opaque_obj = storage[key];
			if (opaque_obj == null)
				return false;

			NSString? str_obj = opaque_obj as NSString;
			if (str_obj == null) {
				throw new Error.PROTOCOL ("Expected “%s” to be a string but got “%s”",
					key.to_string (), Type.from_instance (opaque_obj).name ());
			}

			val = str_obj.str;
			return true;
		}
	}

	private class NSDictionaryRaw : NSObject {
		public int size {
			get {
				return storage.size;
			}
		}

		public Gee.Set<Gee.Map.Entry<NSObject, NSObject>> entries {
			owned get {
				return storage.entries;
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

		public NSDictionaryRaw (Gee.HashMap<NSObject, NSObject>? storage = null) {
			this.storage = (storage != null)
				? storage
				: new Gee.HashMap<NSObject, NSObject> (NSObject.hash_func, NSObject.equal_func);
		}
	}

	private class NSArray : NSObject {
		public int length {
			get {
				return storage.size;
			}
		}

		public Gee.Iterable<NSObject> elements {
			owned get {
				return storage;
			}
		}

		private Gee.ArrayList<NSObject> storage;

		public NSArray (Gee.ArrayList<NSObject>? storage = null) {
			this.storage = (storage != null) ? storage : new Gee.ArrayList<NSObject> (NSObject.equal_func);
		}
	}

	private class NSDate : NSObject {
		public double time {
			get;
			private set;
		}

		public NSDate (double time) {
			this.time = time;
		}
	}

	private class NSError : NSObject {
		public NSString domain {
			get;
			private set;
		}

		public int64 code {
			get;
			private set;
		}

		public NSDictionary user_info {
			get;
			private set;
		}

		public NSError (NSString domain, int64 code, NSDictionary user_info) {
			this.domain = domain;
			this.code = code;
			this.user_info = user_info;
		}
	}

	namespace NSKeyedArchive {
		private Gee.HashMap<Type, EncodeFunc> encoders;
		private Gee.HashMap<string, DecodeFunc> decoders;

		private const string[] DICTIONARY_CLASS = { "NSDictionary", "NSObject" };

		[CCode (has_target = false)]
		private delegate PlistUid EncodeFunc (NSObject instance, EncodingContext ctx);

		[CCode (has_target = false)]
		private delegate NSObject DecodeFunc (PlistDict instance, DecodingContext ctx) throws Error, PlistError;

		private static uint8[] encode (NSObject? obj) {
			if (obj == null)
				return new uint8[0];

			ensure_encoders_registered ();

			var objects = new PlistArray ();
			objects.add_string ("$null");

			var ctx = new EncodingContext (objects);

			var top = new PlistDict ();
			top.set_uid ("root", encode_value (obj, ctx));

			var plist = new Plist ();
			plist.set_integer ("$version", 100000);
			plist.set_array ("$objects", objects);
			plist.set_string ("$archiver", "NSKeyedArchiver");
			plist.set_dict ("$top", top);

			return plist.to_binary ();
		}

		private static PlistUid encode_value (NSObject? obj, EncodingContext ctx) {
			if (obj == null)
				return new PlistUid (0);

			var type = Type.from_instance (obj);
			var encode_object = encoders[type];
			if (encode_object == null)
				critical ("Missing NSKeyedArchive encoder for type “%s”", type.name ());

			return encode_object (obj, ctx);
		}

		private static NSObject? decode (uint8[] data) throws Error {
			ensure_decoders_registered ();

			try {
				var plist = new Plist.from_binary (data);

				var ctx = new DecodingContext (plist.get_array ("$objects"));

				return decode_value (plist.get_dict ("$top").get_uid ("root"), ctx);
			} catch (PlistError e) {
				throw new Error.PROTOCOL ("%s", e.message);
			}
		}

		private static NSObject? decode_value (PlistUid index, DecodingContext ctx) throws Error, PlistError {
			var uid = index.uid;
			if (uid == 0)
				return null;

			var objects = ctx.objects;

			Value * val = objects.get_value ((int) uid);
			Type t = val.type ();

			if (t == typeof (bool))
				return new NSNumber.from_boolean (val.get_boolean ());

			if (t == typeof (int64))
				return new NSNumber.from_integer (val.get_int64 ());

			if (t == typeof (string))
				return new NSString (val.get_string ());

			if (t == typeof (PlistDict)) {
				var instance = (PlistDict) val.get_object ();
				var klass = objects.get_dict ((int) instance.get_uid ("$class").uid);
				var decode = get_decoder (klass);
				return decode (instance, ctx);
			}

			throw new Error.NOT_SUPPORTED ("Unsupported NSKeyedArchive type: %s", val.type_name ());
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

			throw new Error.NOT_SUPPORTED ("Missing NSKeyedArchive decoder for type “%s”", klass.get_string ("$classname"));
		}

		private static void ensure_encoders_registered () {
			if (encoders != null)
				return;

			encoders = new Gee.HashMap<Type, EncodeFunc> ();
			encoders[typeof (NSNumber)] = encode_number;
			encoders[typeof (NSString)] = encode_string;
			encoders[typeof (NSDictionary)] = encode_dictionary;
		}

		private static void ensure_decoders_registered () {
			if (decoders != null)
				return;

			decoders = new Gee.HashMap<string, DecodeFunc> ();
			decoders["NSDictionary"] = decode_dictionary;
			decoders["NSArray"] = decode_array;
			decoders["NSDate"] = decode_date;
			decoders["NSError"] = decode_error;
		}

		private static PlistUid encode_number (NSObject instance, EncodingContext ctx) {
			int64 val = ((NSNumber) instance).integer;

			var uid = ctx.find_existing_object (e => e.holds (typeof (int64)) && e.get_int64 () == val);
			if (uid != null)
				return uid;

			var objects = ctx.objects;
			uid = new PlistUid (objects.length);
			objects.add_integer (val);
			return uid;
		}

		private static PlistUid encode_string (NSObject instance, EncodingContext ctx) {
			string str = ((NSString) instance).str;

			var uid = ctx.find_existing_object (e => e.holds (typeof (string)) && e.get_string () == str);
			if (uid != null)
				return uid;

			var objects = ctx.objects;
			uid = new PlistUid (objects.length);
			objects.add_string (str);
			return uid;
		}

		private static PlistUid encode_dictionary (NSObject instance, EncodingContext ctx) {
			NSDictionary dict = (NSDictionary) instance;

			var object = new PlistDict ();
			var uid = ctx.add_object (object);

			var keys = new PlistArray ();
			var objs = new PlistArray ();
			foreach (var entry in dict.entries) {
				var key = encode_value (new NSString (entry.key), ctx);
				var obj = encode_value (entry.value, ctx);

				keys.add_uid (key);
				objs.add_uid (obj);
			}
			object.set_array ("NS.keys", keys);
			object.set_array ("NS.objects", objs);
			object.set_uid ("$class", ctx.get_class (DICTIONARY_CLASS));

			return uid;
		}

		private static NSObject decode_dictionary (PlistDict instance, DecodingContext ctx) throws Error, PlistError {
			var keys = instance.get_array ("NS.keys");
			var objs = instance.get_array ("NS.objects");

			int n = keys.length;

			var string_keys = new Gee.ArrayList<string> ();
			for (int i = 0; i != n; i++) {
				var key = decode_value (keys.get_uid (i), ctx) as NSString;
				if (key is NSString)
					string_keys.add (key.str);
				else
					break;
			}

			if (string_keys.size == n) {
				var storage = new Gee.HashMap<string, NSObject> ();

				for (int i = 0; i != n; i++)
					storage[string_keys[i]] = decode_value (objs.get_uid (i), ctx);

				return new NSDictionary (storage);
			} else {
				var storage = new Gee.HashMap<NSObject, NSObject> (NSObject.hash_func, NSObject.equal_func);

				for (int i = 0; i != n; i++) {
					var key = decode_value (keys.get_uid (i), ctx);
					var obj = decode_value (objs.get_uid (i), ctx);

					storage[key] = obj;
				}

				return new NSDictionaryRaw (storage);
			}
		}

		private static NSObject decode_array (PlistDict instance, DecodingContext ctx) throws Error, PlistError {
			var objs = instance.get_array ("NS.objects");

			var storage = new Gee.ArrayList<NSObject> (NSObject.equal_func);

			var n = objs.length;
			for (int i = 0; i != n; i++) {
				var obj = decode_value (objs.get_uid (i), ctx);

				storage.add (obj);
			}

			return new NSArray (storage);
		}

		private static NSObject decode_date (PlistDict instance, DecodingContext ctx) throws Error, PlistError {
			var time = instance.get_double ("NS.time");

			return new NSDate (time);
		}

		private static NSObject decode_error (PlistDict instance, DecodingContext ctx) throws Error, PlistError {
			NSString? domain = decode_value (instance.get_uid ("NSDomain"), ctx) as NSString;
			if (domain == null)
				throw new Error.PROTOCOL ("Malformed NSError");

			int64 code = instance.get_integer ("NSCode");

			NSObject? user_info = decode_value (instance.get_uid ("NSUserInfo"), ctx);
			if (user_info != null && !(user_info is NSDictionary))
				throw new Error.PROTOCOL ("Malformed NSError");

			return new NSError (domain, code, (NSDictionary) user_info);
		}

		private class EncodingContext {
			public PlistArray objects;

			private Gee.HashMap<string, PlistUid> classes = new Gee.HashMap<string, PlistUid> ();

			public delegate void AddObjectFunc (PlistArray objects);

			public EncodingContext (PlistArray objects) {
				this.objects = objects;
			}

			public PlistUid? find_existing_object (Gee.Predicate<Value *> predicate) {
				int64 uid = 0;
				foreach (var e in objects.elements) {
					if (uid > 0 && predicate (e))
						return new PlistUid (uid);
					uid++;
				}

				return null;
			}

			public PlistUid add_object (PlistDict obj) {
				var uid = new PlistUid (objects.length);
				objects.add_dict (obj);
				return uid;
			}

			public PlistUid get_class (string[] description) {
				var canonical_name = description[0];

				var uid = classes[canonical_name];
				if (uid != null)
					return uid;

				var spec = new PlistDict ();

				var hierarchy = new PlistArray ();
				foreach (var name in description)
					hierarchy.add_string (name);
				spec.set_array ("$classes", hierarchy);

				spec.set_string ("$classname", canonical_name);

				uid = add_object (spec);
				classes[canonical_name] = uid;

				return uid;
			}
		}

		private class DecodingContext {
			public PlistArray objects;

			public DecodingContext (PlistArray objects) {
				this.objects = objects;
			}
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

	private const size_t PRIMITIVE_DICTIONARY_HEADER_SIZE = 16;

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

		public uint64 read_uint64 () throws Error {
			const size_t n = sizeof (uint64);
			check_available (n);

			uint64 val = uint64.from_little_endian (*((uint64 *) cursor));
			cursor += n;

			return val;
		}

		public double read_double () throws Error {
			uint64 bits = read_uint64 ();
			return *((double *) &bits);
		}

		public unowned uint8[] read_byte_array (size_t n) throws Error {
			check_available (n);

			unowned uint8[] arr = ((uint8[]) cursor)[0:n];
			cursor += n;

			return arr;
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

	private class PrimitiveBuilder {
		public size_t offset {
			get {
				return cursor;
			}
		}

		private ByteArray buffer = new ByteArray.sized (64);
		private size_t cursor = 0;

		public unowned PrimitiveBuilder seek (size_t offset) {
			if (buffer.len < offset) {
				size_t n = offset - buffer.len;
				Memory.set (get_pointer (offset - n, n), 0, n);
			}
			cursor = offset;
			return this;
		}

		public unowned PrimitiveBuilder append_int32 (int32 val) {
			*((int32 *) get_pointer (cursor, sizeof (int32))) = val.to_little_endian ();
			cursor += (uint) sizeof (int32);
			return this;
		}

		public unowned PrimitiveBuilder append_uint32 (uint32 val) {
			*((uint32 *) get_pointer (cursor, sizeof (uint32))) = val.to_little_endian ();
			cursor += (uint) sizeof (uint32);
			return this;
		}

		public unowned PrimitiveBuilder append_int64 (int64 val) {
			*((int64 *) get_pointer (cursor, sizeof (int64))) = val.to_little_endian ();
			cursor += (uint) sizeof (int64);
			return this;
		}

		public unowned PrimitiveBuilder append_uint64 (uint64 val) {
			*((uint64 *) get_pointer (cursor, sizeof (uint64))) = val.to_little_endian ();
			cursor += (uint) sizeof (uint64);
			return this;
		}

		public unowned PrimitiveBuilder append_double (double val) {
			uint64 raw_val = *((uint64 *) &val);
			*((uint64 *) get_pointer (cursor, sizeof (uint64))) = raw_val.to_little_endian ();
			cursor += (uint) sizeof (uint64);
			return this;
		}

		public unowned PrimitiveBuilder append_byte_array (uint8[] array) {
			uint size = array.length;
			Memory.copy (get_pointer (cursor, size), array, size);
			cursor += size;
			return this;
		}

		public unowned PrimitiveBuilder append_string (string str) {
			uint size = str.length;
			Memory.copy (get_pointer (cursor, size), str, size);
			cursor += size;
			return this;
		}

		private uint8 * get_pointer (size_t offset, size_t n) {
			size_t minimum_size = offset + n;
			if (buffer.len < minimum_size)
				buffer.set_size ((uint) minimum_size);

			return (uint8 *) buffer.data + offset;
		}

		public Bytes build () {
			return ByteArray.free_to_bytes ((owned) buffer);
		}
	}
}
