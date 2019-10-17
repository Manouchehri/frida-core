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
				throws DTXError, IOError {
			var service = new DeviceInfoService (channel_provider);

			try {
				yield service.init_async (Priority.DEFAULT, cancellable);
			} catch (GLib.Error e) {
				throw_local_error (e);
			}

			return service;
		}

		private async bool init_async (int io_priority, Cancellable? cancellable) throws DTXError, IOError {
			var connection = yield DTXConnection.obtain (channel_provider, cancellable);

			channel = connection.make_channel ("com.apple.instruments.server.services.deviceinfo");

			return true;
		}

		public async void close (Cancellable? cancellable = null) throws IOError {
			yield channel.close (cancellable);
		}

		public async Gee.ArrayList<ProcessInfo> enumerate_running_processes (Cancellable? cancellable = null) throws IOError {
			var result = new Gee.ArrayList<ProcessInfo> ();
			return result;
		}

		private static void throw_local_error (GLib.Error e) throws DTXError, IOError {
			if (e is DTXError)
				throw (DTXError) e;

			if (e is IOError)
				throw (IOError) e;

			assert_not_reached ();
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

	public class DTXConnection : Object, AsyncInitable {
		public static async DTXConnection obtain (ChannelProvider channel_provider, Cancellable? cancellable)
				throws DTXError, IOError {
			throw new DTXError.PROTOCOL ("Not yet implemented");
		}

		public DTXChannel make_channel (string identifier) {
			return new DTXChannel ();
		}
	}

	public class DTXChannel : Object {
		public async void close (Cancellable? cancellable = null) throws IOError {
		}
	}

	public errordomain DTXError {
		PROTOCOL
	}
}
