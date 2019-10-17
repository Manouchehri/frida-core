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

		private const uint32 DTX_MESSAGE_MAGIC = 0x1f3d5b79U;

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

		private async void process_incoming_fragments () {
			while (true) {
				try {
					var fragment = yield read_fragment ();

				} catch (GLib.Error e) {
					printerr ("DERP: %s\n", e.message);
					return;
				}
			}
		}

		private async Fragment read_fragment () throws Error, IOError {
			var io_priority = Priority.DEFAULT;

			try {
				ssize_t minimum_header_size = 32;

				yield input.fill_async (minimum_header_size, io_priority, io_cancellable);

				uint32 magic = input.read_uint32 (io_cancellable);
				if (magic != DTX_MESSAGE_MAGIC)
					throw new Error.PROTOCOL ("Expected DTX message magic, got 0x%08x", magic);

				var fragment = new Fragment ();

				var header_size = input.read_uint32 (io_cancellable);
				if (header_size < minimum_header_size)
					throw new Error.PROTOCOL ("Expected header size of >= 32, got %u", header_size);
				printerr ("header_size=%u\n", header_size);

				fragment.index = input.read_uint16 (io_cancellable);
				fragment.count = input.read_uint16 (io_cancellable);
				fragment.data_size = input.read_uint32 (io_cancellable);
				fragment.identifier = input.read_uint32 (io_cancellable);
				fragment.conversation_index = input.read_uint32 (io_cancellable);
				fragment.channel_code = input.read_uint32 (io_cancellable);
				fragment.flags = input.read_uint32 (io_cancellable);

				ssize_t extra_header_size = header_size - minimum_header_size;
				if (extra_header_size > 0)
					yield input.skip_async (extra_header_size, io_priority, io_cancellable);


				return fragment;
			} catch (GLib.Error e) {
				if (e is Error)
					throw (Error) e;
				throw new Error.TRANSPORT ("%s", e.message);
			}
		}

		private class Fragment {
			public uint16 index;
			public uint16 count;
			public uint32 data_size;
			public uint32 identifier;
			public uint32 conversation_index;
			public uint32 channel_code;
			public uint32 flags;
		}
	}

	public class DTXChannel : Object {
		public async void close (Cancellable? cancellable = null) throws IOError {
		}
	}
}
