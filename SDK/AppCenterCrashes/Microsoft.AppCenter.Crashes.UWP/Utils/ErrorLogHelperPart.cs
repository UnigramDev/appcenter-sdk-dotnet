// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

using Microsoft.AppCenter.Crashes.Windows.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Text;
using ModelBinary = Microsoft.AppCenter.Crashes.Ingestion.Models.Binary;
using ModelException = Microsoft.AppCenter.Crashes.Ingestion.Models.Exception;
using ModelStackFrame = Microsoft.AppCenter.Crashes.Ingestion.Models.StackFrame;

namespace Microsoft.AppCenter.Crashes.Utils
{
    public partial class ErrorLogHelper
    {
        private const string AddressFormat = "0x{0:x16}";

        // A dword, which is short for "double word," is a data type definition that is specific to Microsoft Windows. As defined in the file windows.h, a dword is an unsigned, 32-bit unit of data.
        private const int DWordSize = 4;

        // These constants come from the PE format described in documentation: https://docs.microsoft.com/en-us/windows/win32/debug/pe-format.

        // Optional Header Windows-Specific field: SizeOfImage is located at the offset 56.
        private const int SizeOfImageOffset = 56;

        // At location 0x3c, the stub has the file offset to the PE signature. This information enables Windows to properly execute the image file.
        private const int SignatureOffsetLocation = 0x3C;

        // At the beginning of an object file, or immediately after the signature of an image file, is a standard COFF file header of 20 bytes.
        private const int COFFFileHeaderSize = 20;

        // Size in bytes of the address that is relative to the image base of the beginning-of-code section when it is loaded into memory.
        private const int BaseOfDataSize = 4;

        internal static ErrorExceptionAndBinaries CreateModelExceptionAndBinaries(System.Exception exception)
        {
            IList<NativeStackFrame> nativeFrames = null;

            if (exception is AggregateException aggregate && aggregate.InnerExceptions.Count > 0 && aggregate.InnerExceptions[aggregate.InnerExceptions.Count - 1] is NativeException native)
            {
                exception = aggregate.InnerExceptions[0];
                nativeFrames = native.Frames;
            }
            else if (exception is NativeException native2)
            {
                nativeFrames = native2.Frames;
            }

            var binaries = new Dictionary<long, ModelBinary>();
            var modelException = ProcessException(exception, null, binaries, nativeFrames);
            return new ErrorExceptionAndBinaries { Binaries = binaries.Count > 0 ? binaries.Values.ToList() : null, Exception = modelException };
        }

        private static string TranslateMessage(string message)
        {
            var parts = message.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            var builder = new StringBuilder();

            foreach (var part in parts)
            {
                builder.AppendLine(TranslateText(part));
            }

            return builder.ToString();
        }

        private static string TranslateText(string text)
        {
            switch (text)
            {
                case "A interface de dispositivo ou nível de recurso especificado não tem suporte neste sistema.":
                case "Указанный интерфейс устройства или уровень компонента не поддерживается в данной системе.":
                case "此系統不支援指定的裝置介面或功能層級。":
                    return "The specified device interface or feature level is not supported on this system.";

                case "Der Text zu diesem Fehlercode wurde nicht gefunden.":
                case "O texto associado a este código de erro não foi localizado.":
                    return "The text associated with this error code could not be found.";

                case "El objeto invocado ha desconectado de sus clientes.":
                case "L'oggetto invocato si è disconnesso dai client corrispondenti.":
                    return "The object invoked has disconnected from its clients.";

                case "Unbekannter Fehler":
                case "Niet nader omschreven fout":
                case "Erreur non spécifiée":
                case "Error no especificado":
                case "Erro não especificado":
                case "Belirtilmemiş hata":
                case "Errore non specificato.":
                case "Nieokreślony błąd.":
                case "Odefinierat fel":
                case "Неопознанная ошибка":
                case "未指定的错误":
                case "지정되지 않은 오류입니다.":
                case "エラーを特定できません":
                    return "Unspecified error";

                case "La instancia de dispositivo de GPU se ha suspendido. Use GetDeviceRemovedReason para averiguar cuál es la acción adecuada.":
                case "Экземпляр устройства GPU приостановлен. Для определения соответствующего действия используйте GetDeviceRemovedReason.":
                    return "The GPU device instance has been suspended. Use GetDeviceRemovedReason to determine the appropriate action.";

                case "Élément introuvable.":
                case "Elemento não encontrado.":
                    return "Element not found.";

                case "Falscher Parameter.":
                case "Paramètre incorrect.":
                case "El parámetro no es correcto.":
                case "Parametro non corretto.":
                case "Parametre hatalı.":
                case "Параметр задан неверно.":
                    return "The parameter is incorrect.";

                case "Geçersiz işaretçi":
                case "Pointeur non valide":
                case "Puntero no válido":
                case "Неправильный указатель":
                    return "Invalid pointer";

                case "Fuera del intervalo actual.":
                case "Fora do intervalo presente.":
                case "En dehors de la plage actuelle.":
                case "Non compreso nell'intervallo presente.":
                case "Выход за пределы диапазона.":
                    return "Out of present range.";

                case "No se puede encontrar el módulo especificado.":
                    return "The specified module could not be found.";

                case "L’application a appelé une interface qui était maintenue en ordre pour un thread différent.":
                case "O aplicativo chamou uma interface marshalled para um outro thread.":
                    return "The application called an interface that was marshalled for a different thread.";

                case "Les ressources mémoire disponibles sont insuffisantes pour exécuter cette opération.":
                case "Le risorse di memoria disponibili insufficienti per completare l'operazione.":
                case "No hay suficientes recursos de memoria disponibles para completar esta operación.":
                case "Недостаточно ресурсов памяти для завершения операции.":
                case "メモリ リソースが不足しているため、この操作を完了できません。":
                    return "Not enough memory resources are available to complete this operation.";

                case "Le serveur RPC n’est pas disponible.":
                case "O servidor RPC não está disponível.":
                case "Serwer RPC jest niedostępny.":
                case "Сервер RPC недоступен.":
                    return "The RPC server is unavailable.";

                case "Zdalne wywołanie procedury nie powiodło się.":
                    return "The remote procedure call failed.";

                case "No se han detectado componentes instalados.":
                    return "No installed components were detected.";

                case "Operação anulada":
                case "Операция прервана":
                    return "Operation aborted";

                case "Разрушительный сбой":
                    return "Catastrophic failure";

                default:
                    return text;
            }
        }

        private static ModelException ProcessException(System.Exception exception, ModelException outerException, Dictionary<long, ModelBinary> seenBinaries, IList<NativeStackFrame> nativeFrames = null)
        {
            var modelException = new ModelException
            {
                Type = exception.GetType().ToString(),
                Message = TranslateMessage(exception.Message),
                StackTrace = exception.StackTrace
            };
            if (exception is AggregateException aggregateException)
            {
                if (aggregateException.InnerExceptions.Count != 0)
                {
                    modelException.InnerExceptions = new List<ModelException>();
                    foreach (var innerException in aggregateException.InnerExceptions)
                    {
                        ProcessException(innerException, modelException, seenBinaries);
                    }
                }
            }
            if (exception.InnerException != null)
            {
                modelException.InnerExceptions = modelException.InnerExceptions ?? new List<ModelException>();
                ProcessException(exception.InnerException, modelException, seenBinaries);
            }

            if (nativeFrames?.Count > 0)
            {
                foreach (var frame in nativeFrames)
                {
                    // Get stack frame address.
                    var crashFrame = new ModelStackFrame
                    {
                        Address = string.Format(CultureInfo.InvariantCulture, AddressFormat, frame.GetNativeIP().ToInt64()),
                    };
                    if (modelException.Frames == null)
                    {
                        modelException.Frames = new List<ModelStackFrame>();
                    }
                    modelException.Frames.Add(crashFrame);

                    // Process binary.
                    var nativeImageBase = frame.GetNativeImageBase().ToInt64();
                    if (seenBinaries.ContainsKey(nativeImageBase) || nativeImageBase == 0)
                    {
                        continue;
                    }
                    var binary = ImageToBinary(frame.GetNativeImageBase());
                    if (binary != null)
                    {
                        seenBinaries[nativeImageBase] = binary;
                    }
                }
            }
            else
            {
                var stackTrace = new StackTrace(exception, true);
                var frames = stackTrace.GetFrames();

                // If there are native frames available, process them to extract image information and frame addresses.
                // The check looks odd, but there is a possibility of frames being null or empty both.
                if (frames != null && frames.Length > 0 && frames[0].HasNativeImage())
                {
                    foreach (var frame in frames)
                    {
                        // Get stack frame address.
                        var crashFrame = new ModelStackFrame
                        {
                            Address = string.Format(CultureInfo.InvariantCulture, AddressFormat, frame.GetNativeIP().ToInt64()),
                        };
                        if (modelException.Frames == null)
                        {
                            modelException.Frames = new List<ModelStackFrame>();
                        }
                        modelException.Frames.Add(crashFrame);

                        // Process binary.
                        var nativeImageBase = frame.GetNativeImageBase().ToInt64();
                        if (seenBinaries.ContainsKey(nativeImageBase) || nativeImageBase == 0)
                        {
                            continue;
                        }
                        var binary = ImageToBinary(frame.GetNativeImageBase());
                        if (binary != null)
                        {
                            seenBinaries[nativeImageBase] = binary;
                        }
                    }
                }
            }

            outerException?.InnerExceptions.Add(modelException);
            return modelException;
        }

        private static unsafe ModelBinary ImageToBinary(IntPtr imageBase)
        {
            var imageSize = GetImageSize(imageBase);
            using (var reader = new PEReader((byte*)imageBase.ToPointer(), imageSize, true))
            {
                var debugDir = reader.ReadDebugDirectory();

                // In some cases debugDir can be empty even though frame.GetNativeImageBase() returns a value.
                if (debugDir.IsEmpty)
                {
                    return null;
                }
                var codeViewEntry = debugDir.First(entry => entry.Type == DebugDirectoryEntryType.CodeView);

                // When attaching a debugger in release, it will break into MissingRuntimeArtifactException, just click continue as it is actually caught and recovered by the lib.
                var codeView = reader.ReadCodeViewDebugDirectoryData(codeViewEntry);
                var pdbPath = Path.GetFileName(codeView.Path);
                var endAddress = imageBase + reader.PEHeaders.PEHeader.SizeOfImage;
                return new ModelBinary
                {
                    StartAddress = string.Format(CultureInfo.InvariantCulture, AddressFormat, imageBase.ToInt64()),
                    EndAddress = string.Format(CultureInfo.InvariantCulture, AddressFormat, endAddress.ToInt64()),
                    Path = pdbPath,
                    Name = string.IsNullOrEmpty(pdbPath) == false ? Path.GetFileNameWithoutExtension(pdbPath) : null,
                    Id = string.Format(CultureInfo.InvariantCulture, "{0:N}-{1}", codeView.Guid, codeView.Age)
                };
            }
        }

        private static int GetImageSize(IntPtr imageBase)
        {
            var peHeaderBytes = new byte[DWordSize];
            Marshal.Copy(imageBase + SignatureOffsetLocation, peHeaderBytes, 0, peHeaderBytes.Length);
            var peHeaderOffset = BitConverter.ToInt32(peHeaderBytes, 0);
            var peOptionalHeaderOffset = peHeaderOffset + BaseOfDataSize + COFFFileHeaderSize;
            var peOptionalHeaderBytes = new byte[DWordSize];
            Marshal.Copy(imageBase + peOptionalHeaderOffset + SizeOfImageOffset, peOptionalHeaderBytes, 0, peOptionalHeaderBytes.Length);
            return BitConverter.ToInt32(peOptionalHeaderBytes, 0);
        }
    }
}