/* Copyright (C) 2014-2019 Tal Aloni <tal.aloni.il@gmail.com>. All rights reserved.
 * 
 * You can redistribute this program and/or modify it under the terms of
 * the GNU Lesser Public License as published by the Free Software Foundation,
 * either version 3 of the License, or (at your option) any later version.
 */

using System;
using System.Buffers;
using System.IO;
using MemoryPools.Memory;
using Utilities;

namespace SMBLibrary
{
    public partial class NTFileSystemAdapter : INTFileStore
    {
        private const int BytesPerSector = 512;
        private const int ClusterSize = 4096;

        private IFileSystem m_fileSystem;

        public event EventHandler<LogEntry> LogEntryAdded;

        public NTFileSystemAdapter(IFileSystem fileSystem)
        {
            m_fileSystem = fileSystem;
        }

        public NTStatus CreateFile(out object handle, out FileStatus fileStatus, IMemoryOwner<char> path, AccessMask desiredAccess, FileAttributes fileAttributes, ShareAccess shareAccess, CreateDisposition createDisposition, CreateOptions createOptions, SecurityContext securityContext)
        {
            handle = null;
            fileStatus = FileStatus.FILE_DOES_NOT_EXIST;
            var createAccess = NTFileStoreHelper.ToCreateFileAccess(desiredAccess, createDisposition);
            var requestedWriteAccess = (createAccess & FileAccess.Write) > 0;

            var forceDirectory = (createOptions & CreateOptions.FILE_DIRECTORY_FILE) > 0;
            var forceFile = (createOptions & CreateOptions.FILE_NON_DIRECTORY_FILE) > 0;

            if (forceDirectory & (createDisposition != CreateDisposition.FILE_CREATE &&
                                  createDisposition != CreateDisposition.FILE_OPEN &&
                                  createDisposition != CreateDisposition.FILE_OPEN_IF &&
                                  createDisposition != CreateDisposition.FILE_SUPERSEDE))
            {
                return NTStatus.STATUS_INVALID_PARAMETER;
            }

            // Windows will try to access named streams (alternate data streams) regardless of the FILE_NAMED_STREAMS flag, we need to prevent this behaviour.
            if (!m_fileSystem.SupportsNamedStreams && path.Memory.Span.IndexOf(':') >=0)
            {
                // Windows Server 2003 will return STATUS_OBJECT_NAME_NOT_FOUND
                return NTStatus.STATUS_NO_SUCH_FILE;
            }

            FileSystemEntry entry = null;
            try
            {
                // tostring
                entry = m_fileSystem.GetEntry(path.Memory.ToString());
            }
            catch (FileNotFoundException)
            {
            }
            catch (DirectoryNotFoundException)
            {
            }
            catch (Exception ex)
            {
                if (ex is IOException || ex is UnauthorizedAccessException)
                {
                    var status = ToNTStatus(ex);
                    Log(Severity.Verbose, "CreateFile: Error retrieving '{0}'. {1}.", path.Memory.ToString(), status);
                    return status;
                }

                throw;
            }

            if (createDisposition == CreateDisposition.FILE_OPEN)
            {
                if (entry == null)
                {
                    return NTStatus.STATUS_NO_SUCH_FILE;
                }

                fileStatus = FileStatus.FILE_EXISTS;
                if (entry.IsDirectory && forceFile)
                {
                    return NTStatus.STATUS_FILE_IS_A_DIRECTORY;
                }

                if (!entry.IsDirectory && forceDirectory)
                {
                    return NTStatus.STATUS_OBJECT_PATH_INVALID;
                }
            }
            else if (createDisposition == CreateDisposition.FILE_CREATE)
            {
                if (entry != null)
                {
                    // File already exists, fail the request 
                    // tostring
                    Log(Severity.Verbose, "CreateFile: File '{0}' already exists.", path.Memory.ToString());
                    fileStatus = FileStatus.FILE_EXISTS;
                    return NTStatus.STATUS_OBJECT_NAME_COLLISION;
                }

                if (!requestedWriteAccess)
                {
                    return NTStatus.STATUS_ACCESS_DENIED;
                }

                try
                {
                    if (forceDirectory)
                    {
                        // tostring
                        Log(Severity.Information, "CreateFile: Creating directory '{0}'", path.Memory.ToString());
                        entry = m_fileSystem.CreateDirectory(path.Memory.ToString());
                    }
                    else
                    {
                        // tostring
                        Log(Severity.Information, "CreateFile: Creating file '{0}'", path.Memory.ToString());
                        entry = m_fileSystem.CreateFile(path.Memory.ToString());
                    }
                }
                catch (Exception ex)
                {
                    if (ex is IOException || ex is UnauthorizedAccessException)
                    {
                        var status = ToNTStatus(ex);
                        // tostring
                        Log(Severity.Verbose, "CreateFile: Error creating '{0}'. {1}.", path.Memory.ToString(), status);
                        return status;
                    }

                    throw;
                }
                fileStatus = FileStatus.FILE_CREATED;
            }
            else if (createDisposition == CreateDisposition.FILE_OPEN_IF ||
                     createDisposition == CreateDisposition.FILE_OVERWRITE ||
                     createDisposition == CreateDisposition.FILE_OVERWRITE_IF ||
                     createDisposition == CreateDisposition.FILE_SUPERSEDE)
            {
                if (entry == null)
                {
                    if (createDisposition == CreateDisposition.FILE_OVERWRITE)
                    {
                        return NTStatus.STATUS_OBJECT_PATH_NOT_FOUND;
                    }

                    if (!requestedWriteAccess)
                    {
                        return NTStatus.STATUS_ACCESS_DENIED;
                    }

                    try
                    {
                        if (forceDirectory)
                        {
                            // tostring
                            Log(Severity.Information, "CreateFile: Creating directory '{0}'", path.Memory.ToString());
                            entry = m_fileSystem.CreateDirectory(path.Memory.ToString());
                        }
                        else
                        {
                            // tostring
                            Log(Severity.Information, "CreateFile: Creating file '{0}'", path.Memory.ToString());
                            entry = m_fileSystem.CreateFile(path.Memory.ToString());
                        }
                    }
                    catch (Exception ex)
                    {
                        if (ex is IOException || ex is UnauthorizedAccessException)
                        {
                            var status = ToNTStatus(ex);
                            // tostring
                            Log(Severity.Verbose, "CreateFile: Error creating '{0}'. {1}.", path.Memory.ToString(), status);
                            return status;
                        }

                        throw;
                    }
                    fileStatus = FileStatus.FILE_CREATED;
                }
                else
                {
                    fileStatus = FileStatus.FILE_EXISTS;
                    if (createDisposition == CreateDisposition.FILE_OPEN_IF)
                    {
                        if (entry.IsDirectory && forceFile)
                        {
                            return NTStatus.STATUS_FILE_IS_A_DIRECTORY;
                        }

                        if (!entry.IsDirectory && forceDirectory)
                        {
                            return NTStatus.STATUS_OBJECT_PATH_INVALID;
                        }
                    }
                    else
                    {
                        if (!requestedWriteAccess)
                        {
                            return NTStatus.STATUS_ACCESS_DENIED;
                        }

                        if (createDisposition == CreateDisposition.FILE_OVERWRITE ||
                            createDisposition == CreateDisposition.FILE_OVERWRITE_IF)
                        {
                            // Truncate the file
                            try
                            {
                                // tostring
                                var temp = m_fileSystem.OpenFile(path.Memory.ToString(), FileMode.Truncate, FileAccess.ReadWrite, FileShare.ReadWrite, FileOptions.None);
                                temp.Close();
                            }
                            catch (Exception ex)
                            {
                                if (ex is IOException || ex is UnauthorizedAccessException)
                                {
                                    var status = ToNTStatus(ex);
                                    // tostring
                                    Log(Severity.Verbose, "CreateFile: Error truncating '{0}'. {1}.", path.Memory.ToString(), status);
                                    return status;
                                }

                                throw;
                            }
                            fileStatus = FileStatus.FILE_OVERWRITTEN;
                        }
                        else if (createDisposition == CreateDisposition.FILE_SUPERSEDE)
                        {
                            // Delete the old file
                            try
                            {
                                // tostring
                                m_fileSystem.Delete(path.Memory.ToString());
                            }
                            catch (Exception ex)
                            {
                                if (ex is IOException || ex is UnauthorizedAccessException)
                                {
                                    var status = ToNTStatus(ex);
                                    // tostring
                                    Log(Severity.Verbose, "CreateFile: Error deleting '{0}'. {1}.", path.Memory.ToString(), status);
                                    return status;
                                }

                                throw;
                            }

                            try
                            {
                                if (forceDirectory)
                                {
                                    // tostring
                                    Log(Severity.Information, "CreateFile: Creating directory '{0}'", path.Memory.ToString());
                                    entry = m_fileSystem.CreateDirectory(path.Memory.ToString());
                                }
                                else
                                {
                                    // tostring
                                    Log(Severity.Information, "CreateFile: Creating file '{0}'", path.Memory.ToString());
                                    entry = m_fileSystem.CreateFile(path.Memory.ToString());
                                }
                            }
                            catch (Exception ex)
                            {
                                if (ex is IOException || ex is UnauthorizedAccessException)
                                {
                                    var status = ToNTStatus(ex);
                                    // tostring
                                    Log(Severity.Verbose, "CreateFile: Error creating '{0}'. {1}.", path.Memory.ToString(), status);
                                    return status;
                                }

                                throw;
                            }
                            fileStatus = FileStatus.FILE_SUPERSEDED;
                        }
                    }
                }
            }
            else
            {
                return NTStatus.STATUS_INVALID_PARAMETER;
            }

            var fileAccess = NTFileStoreHelper.ToFileAccess(desiredAccess);
            Stream stream;
            if (fileAccess == 0 || entry.IsDirectory)
            {
                stream = null;
            }
            else
            {
                // Note that SetFileInformationByHandle/FILE_DISPOSITION_INFO has no effect if the handle was opened with FILE_DELETE_ON_CLOSE.
                var openStatus = OpenFileStream(out stream, path, fileAccess, shareAccess, createOptions);
                if (openStatus != NTStatus.STATUS_SUCCESS)
                {
                    return openStatus;
                }
            }

            var deleteOnClose = (createOptions & CreateOptions.FILE_DELETE_ON_CLOSE) > 0;
            handle = new FileHandle(path, entry.IsDirectory, stream, deleteOnClose);
            if (fileStatus != FileStatus.FILE_CREATED &&
                fileStatus != FileStatus.FILE_OVERWRITTEN &&
                fileStatus != FileStatus.FILE_SUPERSEDED)
            {
                fileStatus = FileStatus.FILE_OPENED;
            }
            return NTStatus.STATUS_SUCCESS;
        }

        private NTStatus OpenFileStream(out Stream stream, IMemoryOwner<char> path, FileAccess fileAccess, ShareAccess shareAccess, CreateOptions openOptions)
        {
            stream = null;
            var fileShare = NTFileStoreHelper.ToFileShare(shareAccess);
            var fileOptions = ToFileOptions(openOptions);
            var fileShareString = fileShare.ToString().Replace(", ", "|");
            var fileOptionsString = ToFileOptionsString(fileOptions);
            try
            {
                // tostring
                stream = m_fileSystem.OpenFile(new string(path.Memory.Span), FileMode.Open, fileAccess, fileShare, fileOptions);
            }
            catch (Exception ex)
            {
                if (ex is IOException || ex is UnauthorizedAccessException)
                {
                    var status = ToNTStatus(ex);
                    // tostring
                    Log(Severity.Verbose, "OpenFile: Cannot open '{0}', Access={1}, Share={2}. NTStatus: {3}.", path.Memory.ToString(), fileAccess, fileShareString, status);
                    return status;
                }

                throw;
            }

            // tostring
            Log(Severity.Information, "OpenFileStream: Opened '{0}', Access={1}, Share={2}, FileOptions={3}", path.Memory.ToString(), fileAccess, fileShareString, fileOptionsString);
            return NTStatus.STATUS_SUCCESS;
        }

        public NTStatus CloseFile(object handle)
        {
            var fileHandle = (FileHandle)handle;
            if (fileHandle.Stream != null)
            {
                Log(Severity.Verbose, "CloseFile: Closing '{0}'.", fileHandle.Path);
                fileHandle.Stream.Close();
            }

            // If the file / directory was created with FILE_DELETE_ON_CLOSE but was not opened (with FileOptions.DeleteOnClose), we should delete it now.
            if (fileHandle.Stream == null && fileHandle.DeleteOnClose)
            {
                try
                {
                    m_fileSystem.Delete(fileHandle.Path.Memory.ToString());
                    Log(Severity.Verbose, "CloseFile: Deleted '{0}'.", fileHandle.Path.Memory);
                }
                catch
                {
                    Log(Severity.Verbose, "CloseFile: Error deleting '{0}'.", fileHandle.Path.Memory);
                }
            }

            return NTStatus.STATUS_SUCCESS;
        }

        public NTStatus ReadFile(out IMemoryOwner<byte> data, object handle, long offset, int maxCount)
        {
            data = null;
            var fileHandle = (FileHandle)handle;
            var path = fileHandle.Path;
            var stream = fileHandle.Stream;
            if (stream == null || !stream.CanRead)
            {
                Log(Severity.Verbose, "ReadFile: Cannot read '{0}', Invalid Operation.", path);
                return NTStatus.STATUS_ACCESS_DENIED;
            }

            if (offset >= stream.Length)
            {
                Log(Severity.Verbose, "ReadFile: Cannot read from '{0}', offset {1} is out of range.", path, offset);
                return NTStatus.STATUS_END_OF_FILE;
            }

            int bytesRead;
            try
            {
                stream.Seek(offset, SeekOrigin.Begin);
                using var buf = Arrays.Rent(maxCount); 
                bytesRead = stream.Read(buf.Memory.Span);
                data = buf.Slice(0, bytesRead);
            }
            catch (Exception ex)
            {
                if (ex is IOException || ex is UnauthorizedAccessException)
                {
                    var status = ToNTStatus(ex);
                    Log(Severity.Verbose, "ReadFile: Cannot read '{0}'. {1}.", path, status);
                    return status;
                }

                throw;
            }

            return NTStatus.STATUS_SUCCESS;
        }

        public NTStatus WriteFile(out int numberOfBytesWritten, object handle, long offset, IMemoryOwner<byte> data)
        {
            numberOfBytesWritten = 0;
            var fileHandle = (FileHandle)handle;
            var path = fileHandle.Path;
            var stream = fileHandle.Stream;
            if (stream == null || !stream.CanWrite)
            {
                Log(Severity.Verbose, "WriteFile: Cannot write '{0}'. Invalid Operation.", path);
                return NTStatus.STATUS_ACCESS_DENIED;
            }

            try
            {
                stream.Seek(offset, SeekOrigin.Begin);
                stream.Write(data.Memory.Span);
            }
            catch (Exception ex)
            {
                if (ex is IOException || ex is UnauthorizedAccessException)
                {
                    var status = ToNTStatus(ex);
                    Log(Severity.Verbose, "WriteFile: Cannot write '{0}'. {1}.", path, status);
                    return status;
                }

                throw;
            }
            numberOfBytesWritten = data.Length();
            return NTStatus.STATUS_SUCCESS;
        }

        public NTStatus FlushFileBuffers(object handle)
        {
            var fileHandle = (FileHandle)handle;
            if (fileHandle.Stream != null)
            {
                fileHandle.Stream.Flush();
            }
            return NTStatus.STATUS_SUCCESS;
        }

        public NTStatus LockFile(object handle, long byteOffset, long length, bool exclusiveLock)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus UnlockFile(object handle, long byteOffset, long length)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus GetSecurityInformation(out SecurityDescriptor result, object handle, SecurityInformation securityInformation)
        {
            result = null;
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus SetSecurityInformation(object handle, SecurityInformation securityInformation, SecurityDescriptor securityDescriptor)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus NotifyChange(out object ioRequest, object handle, NotifyChangeFilter completionFilter, bool watchTree, int outputBufferSize, OnNotifyChangeCompleted onNotifyChangeCompleted, object context)
        {
            ioRequest = null;
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus Cancel(object ioRequest)
        {
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public NTStatus DeviceIOControl(object handle, uint ctlCode, IMemoryOwner<byte> input, out IMemoryOwner<byte> output, int maxOutputLength)
        {
            output = null;
            return NTStatus.STATUS_NOT_SUPPORTED;
        }

        public void Log(Severity severity, string message)
        {
            // To be thread-safe we must capture the delegate reference first
            var handler = LogEntryAdded;
            if (handler != null)
            {
                handler(this, new LogEntry(DateTime.Now, severity, "NT FileSystem Adapter", message));
            }
        }

        public void Log(Severity severity, string message, params object[] args)
        {
            Log(severity, String.Format(message, args));
        }

        /// <param name="exception">IFileSystem exception</param>
        private static NTStatus ToNTStatus(Exception exception)
        {
            if (exception is DirectoryNotFoundException)
            {
                return NTStatus.STATUS_OBJECT_PATH_NOT_FOUND;
            }

            if (exception is FileNotFoundException)
            {
                return NTStatus.STATUS_OBJECT_PATH_NOT_FOUND;
            }

            if (exception is IOException)
            {
                var errorCode = IOExceptionHelper.GetWin32ErrorCode((IOException)exception);
                if (errorCode == (ushort)Win32Error.ERROR_SHARING_VIOLATION)
                {
                    return NTStatus.STATUS_SHARING_VIOLATION;
                }

                if (errorCode == (ushort)Win32Error.ERROR_DISK_FULL)
                {
                    return NTStatus.STATUS_DISK_FULL;
                }

                if (errorCode == (ushort)Win32Error.ERROR_INVALID_NAME)
                {
                    return NTStatus.STATUS_OBJECT_NAME_INVALID;
                }

                if (errorCode == (ushort)Win32Error.ERROR_DIR_NOT_EMPTY)
                {
                    // If a user tries to rename folder1 to folder2 when folder2 already exists, Windows 7 will offer to merge folder1 into folder2.
                    // In such case, Windows 7 will delete folder 1 and will expect STATUS_DIRECTORY_NOT_EMPTY if there are files to merge.
                    return NTStatus.STATUS_DIRECTORY_NOT_EMPTY;
                }

                if (errorCode == (ushort)Win32Error.ERROR_BAD_PATHNAME)
                {
                    return NTStatus.STATUS_OBJECT_PATH_INVALID;
                }

                if (errorCode == (ushort)Win32Error.ERROR_ALREADY_EXISTS)
                {
                    // According to [MS-FSCC], FileRenameInformation MUST return STATUS_OBJECT_NAME_COLLISION when the specified name already exists and ReplaceIfExists is zero.
                    return NTStatus.STATUS_OBJECT_NAME_COLLISION;
                }

                return NTStatus.STATUS_DATA_ERROR;
            }

            if (exception is UnauthorizedAccessException)
            {
                return NTStatus.STATUS_ACCESS_DENIED;
            }

            return NTStatus.STATUS_DATA_ERROR;
        }

        private static FileOptions ToFileOptions(CreateOptions createOptions)
        {
            const FileOptions FILE_FLAG_OPEN_REPARSE_POINT = (FileOptions)0x00200000;
            const FileOptions FILE_FLAG_NO_BUFFERING = (FileOptions)0x20000000;
            
            var result = FileOptions.None;
            if ((createOptions & CreateOptions.FILE_OPEN_REPARSE_POINT) > 0)
            {
                result |= FILE_FLAG_OPEN_REPARSE_POINT;
            }
            if ((createOptions & CreateOptions.FILE_NO_INTERMEDIATE_BUFFERING) > 0)
            {
                result |= FILE_FLAG_NO_BUFFERING;
            }
            if ((createOptions & CreateOptions.FILE_RANDOM_ACCESS) > 0)
            {
                result |= FileOptions.RandomAccess;
            }
            if ((createOptions & CreateOptions.FILE_SEQUENTIAL_ONLY) > 0)
            {
                result |= FileOptions.SequentialScan;
            }
            if ((createOptions & CreateOptions.FILE_WRITE_THROUGH) > 0)
            {
                result |= FileOptions.WriteThrough;
            }
            if ((createOptions & CreateOptions.FILE_DELETE_ON_CLOSE) > 0)
            {
                result |= FileOptions.DeleteOnClose;
            }

            return result;
        }

        private static string ToFileOptionsString(FileOptions options)
        {
            var result = String.Empty;
            const FileOptions FILE_FLAG_OPEN_REPARSE_POINT = (FileOptions)0x00200000;
            const FileOptions FILE_FLAG_NO_BUFFERING = (FileOptions)0x20000000;
            if ((options & FILE_FLAG_OPEN_REPARSE_POINT) > 0)
            {
                result += "ReparsePoint|";
                options &= ~FILE_FLAG_OPEN_REPARSE_POINT;
            }
            if ((options & FILE_FLAG_NO_BUFFERING) > 0)
            {
                result += "NoBuffering|";
                options &= ~FILE_FLAG_NO_BUFFERING;
            }

            if (result == String.Empty || options != FileOptions.None)
            {
                result += options.ToString().Replace(", ", "|");
            }
            result = result.TrimEnd(new[] { '|' });
            return result;
        }

        /// <summary>
        /// Will return a virtual allocation size, assuming 4096 bytes per cluster
        /// </summary>
        public static ulong GetAllocationSize(ulong size)
        {
            return (ulong)Math.Ceiling((double)size / ClusterSize) * ClusterSize;
        }
    }
}
