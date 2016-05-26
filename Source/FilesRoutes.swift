
/* Autogenerated. Do not edit. */

/// Routes for the files namespace
public class FilesRoutes {
    public let client: DropboxTransportClient
    init(client: DropboxTransportClient) {
        self.client = client
    }
    /**
        Copy a file or folder to a different location in the user's Dropbox. If the source path is a folder all its
        contents will be copied.

        - parameter fromPath: Path in the user's Dropbox to be copied or moved.
        - parameter toPath: Path in the user's Dropbox that is the destination.

         - returns: Through the response callback, the caller will receive a `Files.Metadata` object on success or a
        `Files.RelocationError` object on failure.
    */
    public func copy(fromPath fromPath: String, toPath: String) -> DropboxRpcRequest<Files.MetadataSerializer, Files.RelocationErrorSerializer> {
        let request = Files.RelocationArg(fromPath: fromPath, toPath: toPath)
        return DropboxRpcRequest(client: self.client, host: "meta", route: "/files/copy", params: Files.RelocationArgSerializer().serialize(request), responseSerializer: Files.MetadataSerializer(), errorSerializer: Files.RelocationErrorSerializer())
    }
    /**
        Create a folder at a given path.

        - parameter path: Path in the user's Dropbox to create.

         - returns: Through the response callback, the caller will receive a `Files.FolderMetadata` object on success or
        a `Files.CreateFolderError` object on failure.
    */
    public func createFolder(path path: String) -> DropboxRpcRequest<Files.FolderMetadataSerializer, Files.CreateFolderErrorSerializer> {
        let request = Files.CreateFolderArg(path: path)
        return DropboxRpcRequest(client: self.client, host: "meta", route: "/files/create_folder", params: Files.CreateFolderArgSerializer().serialize(request), responseSerializer: Files.FolderMetadataSerializer(), errorSerializer: Files.CreateFolderErrorSerializer())
    }
    /**
        Delete the file or folder at a given path. If the path is a folder, all its contents will be deleted too. A
        successful response indicates that the file or folder was deleted. The returned metadata will be the
        corresponding FileMetadata or FolderMetadata for the item at time of deletion, and not a DeletedMetadata object.

        - parameter path: Path in the user's Dropbox to delete.

         - returns: Through the response callback, the caller will receive a `Files.Metadata` object on success or a
        `Files.DeleteError` object on failure.
    */
    public func delete(path path: String) -> DropboxRpcRequest<Files.MetadataSerializer, Files.DeleteErrorSerializer> {
        let request = Files.DeleteArg(path: path)
        return DropboxRpcRequest(client: self.client, host: "meta", route: "/files/delete", params: Files.DeleteArgSerializer().serialize(request), responseSerializer: Files.MetadataSerializer(), errorSerializer: Files.DeleteErrorSerializer())
    }
    /**
        Download a file from a user's Dropbox.

        - parameter path: The path of the file to download.
        - parameter rev: Deprecated. Please specify revision in path instead
        - parameter destination: A closure used to compute the destination, given the temporary file location and the
        response
        - parameter overwrite: A boolean to set behavior in the event of a naming conflict. `True` will overwrite
        conflicting file at destination. `False` will take no action (but if left unhandled in destination closure, an
        NSError will be thrown).

         - returns: Through the response callback, the caller will receive a `Files.FileMetadata` object on success or a
        `Files.DownloadError` object on failure.
    */
    public func download(path path: String, rev: String? = nil, destination: (NSURL, NSHTTPURLResponse) -> NSURL, overwrite: Bool = false) -> DropboxDownloadRequest<Files.FileMetadataSerializer, Files.DownloadErrorSerializer> {
        let request = Files.DownloadArg(path: path, rev: rev)
        return DropboxDownloadRequest(client: self.client, host: "content", route: "/files/download", params: Files.DownloadArgSerializer().serialize(request), responseSerializer: Files.FileMetadataSerializer(), errorSerializer: Files.DownloadErrorSerializer(), destination: destination, overwrite: overwrite)
    }
    /**
        Returns the metadata for a file or folder. Note: Metadata for the root folder is unsupported.

        - parameter path: The path of a file or folder on Dropbox.
        - parameter includeMediaInfo: If true, mediaInfo in FileMetadata is set for photo and video.

         - returns: Through the response callback, the caller will receive a `Files.Metadata` object on success or a
        `Files.GetMetadataError` object on failure.
    */
    public func getMetadata(path path: String, includeMediaInfo: Bool = false) -> DropboxRpcRequest<Files.MetadataSerializer, Files.GetMetadataErrorSerializer> {
        let request = Files.GetMetadataArg(path: path, includeMediaInfo: includeMediaInfo)
        return DropboxRpcRequest(client: self.client, host: "meta", route: "/files/get_metadata", params: Files.GetMetadataArgSerializer().serialize(request), responseSerializer: Files.MetadataSerializer(), errorSerializer: Files.GetMetadataErrorSerializer())
    }
    /**
        Get a preview for a file. Currently previews are only generated for the files with  the following extensions:
        .doc, .docx, .docm, .ppt, .pps, .ppsx, .ppsm, .pptx, .pptm,  .xls, .xlsx, .xlsm, .rtf

        - parameter path: The path of the file to preview.
        - parameter rev: Deprecated. Please specify revision in path instead
        - parameter destination: A closure used to compute the destination, given the temporary file location and the
        response
        - parameter overwrite: A boolean to set behavior in the event of a naming conflict. `True` will overwrite
        conflicting file at destination. `False` will take no action (but if left unhandled in destination closure, an
        NSError will be thrown).

         - returns: Through the response callback, the caller will receive a `Files.FileMetadata` object on success or a
        `Files.PreviewError` object on failure.
    */
    public func getPreview(path path: String, rev: String? = nil, destination: (NSURL, NSHTTPURLResponse) -> NSURL, overwrite: Bool = false) -> DropboxDownloadRequest<Files.FileMetadataSerializer, Files.PreviewErrorSerializer> {
        let request = Files.PreviewArg(path: path, rev: rev)
        return DropboxDownloadRequest(client: self.client, host: "content", route: "/files/get_preview", params: Files.PreviewArgSerializer().serialize(request), responseSerializer: Files.FileMetadataSerializer(), errorSerializer: Files.PreviewErrorSerializer(), destination: destination, overwrite: overwrite)
    }
    /**
        Get a thumbnail for an image. This method currently supports files with the following file extensions: jpg,
        jpeg, png, tiff, tif, gif and bmp. Photos that are larger than 20MB in size won't be converted to a thumbnail.

        - parameter path: The path to the image file you want to thumbnail.
        - parameter format: The format for the thumbnail image, jpeg (default) or png. For  images that are photos, jpeg
        should be preferred, while png is  better for screenshots and digital arts.
        - parameter size: The size for the thumbnail image.
        - parameter destination: A closure used to compute the destination, given the temporary file location and the
        response
        - parameter overwrite: A boolean to set behavior in the event of a naming conflict. `True` will overwrite
        conflicting file at destination. `False` will take no action (but if left unhandled in destination closure, an
        NSError will be thrown).

         - returns: Through the response callback, the caller will receive a `Files.FileMetadata` object on success or a
        `Files.ThumbnailError` object on failure.
    */
    public func getThumbnail(path path: String, format: Files.ThumbnailFormat = .Jpeg, size: Files.ThumbnailSize = .W64h64, destination: (NSURL, NSHTTPURLResponse) -> NSURL, overwrite: Bool = false) -> DropboxDownloadRequest<Files.FileMetadataSerializer, Files.ThumbnailErrorSerializer> {
        let request = Files.ThumbnailArg(path: path, format: format, size: size)
        return DropboxDownloadRequest(client: self.client, host: "content", route: "/files/get_thumbnail", params: Files.ThumbnailArgSerializer().serialize(request), responseSerializer: Files.FileMetadataSerializer(), errorSerializer: Files.ThumbnailErrorSerializer(), destination: destination, overwrite: overwrite)
    }
    /**
        Returns the contents of a folder.

        - parameter path: The path to the folder you want to see the contents of.
        - parameter recursive: If true, the list folder operation will be applied recursively to all subfolders and the
        response will contain contents of all subfolders.
        - parameter includeMediaInfo: If true, mediaInfo in FileMetadata is set for photo and video.
        - parameter includeDeleted: If true, the results will include entries for files and folders that used to exist
        but were deleted.

         - returns: Through the response callback, the caller will receive a `Files.ListFolderResult` object on success
        or a `Files.ListFolderError` object on failure.
    */
    public func listFolder(path path: String, recursive: Bool = false, includeMediaInfo: Bool = false, includeDeleted: Bool = false) -> DropboxRpcRequest<Files.ListFolderResultSerializer, Files.ListFolderErrorSerializer> {
        let request = Files.ListFolderArg(path: path, recursive: recursive, includeMediaInfo: includeMediaInfo, includeDeleted: includeDeleted)
        return DropboxRpcRequest(client: self.client, host: "meta", route: "/files/list_folder", params: Files.ListFolderArgSerializer().serialize(request), responseSerializer: Files.ListFolderResultSerializer(), errorSerializer: Files.ListFolderErrorSerializer())
    }
    /**
        Once a cursor has been retrieved from listFolder, use this to paginate through all files and retrieve updates to
        the folder.

        - parameter cursor: The cursor returned by your last call to listFolder or listFolderContinue.

         - returns: Through the response callback, the caller will receive a `Files.ListFolderResult` object on success
        or a `Files.ListFolderContinueError` object on failure.
    */
    public func listFolderContinue(cursor cursor: String) -> DropboxRpcRequest<Files.ListFolderResultSerializer, Files.ListFolderContinueErrorSerializer> {
        let request = Files.ListFolderContinueArg(cursor: cursor)
        return DropboxRpcRequest(client: self.client, host: "meta", route: "/files/list_folder/continue", params: Files.ListFolderContinueArgSerializer().serialize(request), responseSerializer: Files.ListFolderResultSerializer(), errorSerializer: Files.ListFolderContinueErrorSerializer())
    }
    /**
        A way to quickly get a cursor for the folder's state. Unlike listFolder, listFolderGetLatestCursor doesn't
        return any entries. This endpoint is for app which only needs to know about new files and modifications and
        doesn't need to know about files that already exist in Dropbox.

        - parameter path: The path to the folder you want to see the contents of.
        - parameter recursive: If true, the list folder operation will be applied recursively to all subfolders and the
        response will contain contents of all subfolders.
        - parameter includeMediaInfo: If true, mediaInfo in FileMetadata is set for photo and video.
        - parameter includeDeleted: If true, the results will include entries for files and folders that used to exist
        but were deleted.

         - returns: Through the response callback, the caller will receive a `Files.ListFolderGetLatestCursorResult`
        object on success or a `Files.ListFolderError` object on failure.
    */
    public func listFolderGetLatestCursor(path path: String, recursive: Bool = false, includeMediaInfo: Bool = false, includeDeleted: Bool = false) -> DropboxRpcRequest<Files.ListFolderGetLatestCursorResultSerializer, Files.ListFolderErrorSerializer> {
        let request = Files.ListFolderArg(path: path, recursive: recursive, includeMediaInfo: includeMediaInfo, includeDeleted: includeDeleted)
        return DropboxRpcRequest(client: self.client, host: "meta", route: "/files/list_folder/get_latest_cursor", params: Files.ListFolderArgSerializer().serialize(request), responseSerializer: Files.ListFolderGetLatestCursorResultSerializer(), errorSerializer: Files.ListFolderErrorSerializer())
    }
    /**
        A longpoll endpoint to wait for changes on an account. In conjunction with listFolder, this call gives you a
        low-latency way to monitor an account for file changes. The connection will block until there are changes
        available or a timeout occurs. This endpoint is useful mostly for client-side apps. If you're looking for
        server-side notifications, check out our webhooks documentation
        https://www.dropbox.com/developers/reference/webhooks.

        - parameter cursor: A cursor as returned by listFolder or listFolderContinue. Cursors retrieved by setting
        includeMediaInfo in ListFolderArg to true are not supported.
        - parameter timeout: A timeout in seconds. The request will block for at most this length of time, plus up to 90
        seconds of random jitter added to avoid the thundering herd problem. Care should be taken when using this
        parameter, as some network infrastructure does not support long timeouts.

         - returns: Through the response callback, the caller will receive a `Files.ListFolderLongpollResult` object on
        success or a `Files.ListFolderLongpollError` object on failure.
    */
    public func listFolderLongpoll(cursor cursor: String, timeout: UInt64 = 30) -> DropboxRpcRequest<Files.ListFolderLongpollResultSerializer, Files.ListFolderLongpollErrorSerializer> {
        let request = Files.ListFolderLongpollArg(cursor: cursor, timeout: timeout)
        return DropboxRpcRequest(client: self.client, host: "notify", route: "/files/list_folder/longpoll", params: Files.ListFolderLongpollArgSerializer().serialize(request), responseSerializer: Files.ListFolderLongpollResultSerializer(), errorSerializer: Files.ListFolderLongpollErrorSerializer())
    }
    /**
        Return revisions of a file

        - parameter path: The path to the file you want to see the revisions of.
        - parameter limit: The maximum number of revision entries returned.

         - returns: Through the response callback, the caller will receive a `Files.ListRevisionsResult` object on
        success or a `Files.ListRevisionsError` object on failure.
    */
    public func listRevisions(path path: String, limit: UInt64 = 10) -> DropboxRpcRequest<Files.ListRevisionsResultSerializer, Files.ListRevisionsErrorSerializer> {
        let request = Files.ListRevisionsArg(path: path, limit: limit)
        return DropboxRpcRequest(client: self.client, host: "meta", route: "/files/list_revisions", params: Files.ListRevisionsArgSerializer().serialize(request), responseSerializer: Files.ListRevisionsResultSerializer(), errorSerializer: Files.ListRevisionsErrorSerializer())
    }
    /**
        Move a file or folder to a different location in the user's Dropbox. If the source path is a folder all its
        contents will be moved.

        - parameter fromPath: Path in the user's Dropbox to be copied or moved.
        - parameter toPath: Path in the user's Dropbox that is the destination.

         - returns: Through the response callback, the caller will receive a `Files.Metadata` object on success or a
        `Files.RelocationError` object on failure.
    */
    public func move(fromPath fromPath: String, toPath: String) -> DropboxRpcRequest<Files.MetadataSerializer, Files.RelocationErrorSerializer> {
        let request = Files.RelocationArg(fromPath: fromPath, toPath: toPath)
        return DropboxRpcRequest(client: self.client, host: "meta", route: "/files/move", params: Files.RelocationArgSerializer().serialize(request), responseSerializer: Files.MetadataSerializer(), errorSerializer: Files.RelocationErrorSerializer())
    }
    /**
        Permanently delete the file or folder at a given path (see https://www.dropbox.com/en/help/40). Note: This
        endpoint is only available for Dropbox Business apps.

        - parameter path: Path in the user's Dropbox to delete.

         - returns: Through the response callback, the caller will receive a `Void` object on success or a
        `Files.DeleteError` object on failure.
    */
    public func permanentlyDelete(path path: String) -> DropboxRpcRequest<VoidSerializer, Files.DeleteErrorSerializer> {
        let request = Files.DeleteArg(path: path)
        return DropboxRpcRequest(client: self.client, host: "meta", route: "/files/permanently_delete", params: Files.DeleteArgSerializer().serialize(request), responseSerializer: Serialization._VoidSerializer, errorSerializer: Files.DeleteErrorSerializer())
    }
    /**
        Restore a file to a specific revision

        - parameter path: The path to the file you want to restore.
        - parameter rev: The revision to restore for the file.

         - returns: Through the response callback, the caller will receive a `Files.FileMetadata` object on success or a
        `Files.RestoreError` object on failure.
    */
    public func restore(path path: String, rev: String) -> DropboxRpcRequest<Files.FileMetadataSerializer, Files.RestoreErrorSerializer> {
        let request = Files.RestoreArg(path: path, rev: rev)
        return DropboxRpcRequest(client: self.client, host: "meta", route: "/files/restore", params: Files.RestoreArgSerializer().serialize(request), responseSerializer: Files.FileMetadataSerializer(), errorSerializer: Files.RestoreErrorSerializer())
    }
    /**
        Searches for files and folders.

        - parameter path: The path in the user's Dropbox to search. Should probably be a folder.
        - parameter query: The string to search for. The search string is split on spaces into multiple tokens. For file
        name searching, the last token is used for prefix matching (i.e. "bat c" matches "bat cave" but not "batman
        car").
        - parameter start: The starting index within the search results (used for paging).
        - parameter maxResults: The maximum number of search results to return.
        - parameter mode: The search mode (filename, filename_and_content, or deleted_filename). Note that searching
        file content is only available for Dropbox Business accounts.

         - returns: Through the response callback, the caller will receive a `Files.SearchResult` object on success or a
        `Files.SearchError` object on failure.
    */
    public func search(path path: String, query: String, start: UInt64 = 0, maxResults: UInt64 = 100, mode: Files.SearchMode = .Filename) -> DropboxRpcRequest<Files.SearchResultSerializer, Files.SearchErrorSerializer> {
        let request = Files.SearchArg(path: path, query: query, start: start, maxResults: maxResults, mode: mode)
        return DropboxRpcRequest(client: self.client, host: "meta", route: "/files/search", params: Files.SearchArgSerializer().serialize(request), responseSerializer: Files.SearchResultSerializer(), errorSerializer: Files.SearchErrorSerializer())
    }
    /**
        Create a new file with the contents provided in the request. Do not use this to upload a file larger than 150
        MB. Instead, create an upload session with uploadSessionStart.

        - parameter path: Path in the user's Dropbox to save the file.
        - parameter mode: Selects what to do if the file already exists.
        - parameter autorename: If there's a conflict, as determined by mode, have the Dropbox server try to autorename
        the file to avoid conflict.
        - parameter clientModified: The value to store as the clientModified timestamp. Dropbox automatically records
        the time at which the file was written to the Dropbox servers. It can also record an additional timestamp,
        provided by Dropbox desktop clients, mobile clients, and API apps of when the file was actually created or
        modified.
        - parameter mute: Normally, users are made aware of any file modifications in their Dropbox account via
        notifications in the client software. If true, this tells the clients that this modification shouldn't result in
        a user notification.
        - parameter body: The file to upload, as an NSData object

         - returns: Through the response callback, the caller will receive a `Files.FileMetadata` object on success or a
        `Files.UploadError` object on failure.
    */
    public func upload(path path: String, mode: Files.WriteMode = .Add, autorename: Bool = false, clientModified: NSDate? = nil, mute: Bool = false, body: NSData) -> DropboxUploadRequest<Files.FileMetadataSerializer, Files.UploadErrorSerializer> {
        let request = Files.CommitInfo(path: path, mode: mode, autorename: autorename, clientModified: clientModified, mute: mute)
        return DropboxUploadRequest(client: self.client, host: "content", route: "/files/upload", params: Files.CommitInfoSerializer().serialize(request), responseSerializer: Files.FileMetadataSerializer(), errorSerializer: Files.UploadErrorSerializer(), body: .Data(body))
    }
    /**
        Create a new file with the contents provided in the request. Do not use this to upload a file larger than 150
        MB. Instead, create an upload session with uploadSessionStart.

        - parameter path: Path in the user's Dropbox to save the file.
        - parameter mode: Selects what to do if the file already exists.
        - parameter autorename: If there's a conflict, as determined by mode, have the Dropbox server try to autorename
        the file to avoid conflict.
        - parameter clientModified: The value to store as the clientModified timestamp. Dropbox automatically records
        the time at which the file was written to the Dropbox servers. It can also record an additional timestamp,
        provided by Dropbox desktop clients, mobile clients, and API apps of when the file was actually created or
        modified.
        - parameter mute: Normally, users are made aware of any file modifications in their Dropbox account via
        notifications in the client software. If true, this tells the clients that this modification shouldn't result in
        a user notification.
        - parameter body: The file to upload, as an NSURL object

         - returns: Through the response callback, the caller will receive a `Files.FileMetadata` object on success or a
        `Files.UploadError` object on failure.
    */
    public func upload(path path: String, mode: Files.WriteMode = .Add, autorename: Bool = false, clientModified: NSDate? = nil, mute: Bool = false, body: NSURL) -> DropboxUploadRequest<Files.FileMetadataSerializer, Files.UploadErrorSerializer> {
        let request = Files.CommitInfo(path: path, mode: mode, autorename: autorename, clientModified: clientModified, mute: mute)
        return DropboxUploadRequest(client: self.client, host: "content", route: "/files/upload", params: Files.CommitInfoSerializer().serialize(request), responseSerializer: Files.FileMetadataSerializer(), errorSerializer: Files.UploadErrorSerializer(), body: .File(body))
    }
    /**
        Create a new file with the contents provided in the request. Do not use this to upload a file larger than 150
        MB. Instead, create an upload session with uploadSessionStart.

        - parameter path: Path in the user's Dropbox to save the file.
        - parameter mode: Selects what to do if the file already exists.
        - parameter autorename: If there's a conflict, as determined by mode, have the Dropbox server try to autorename
        the file to avoid conflict.
        - parameter clientModified: The value to store as the clientModified timestamp. Dropbox automatically records
        the time at which the file was written to the Dropbox servers. It can also record an additional timestamp,
        provided by Dropbox desktop clients, mobile clients, and API apps of when the file was actually created or
        modified.
        - parameter mute: Normally, users are made aware of any file modifications in their Dropbox account via
        notifications in the client software. If true, this tells the clients that this modification shouldn't result in
        a user notification.
        - parameter body: The file to upload, as an NSInputStream object

         - returns: Through the response callback, the caller will receive a `Files.FileMetadata` object on success or a
        `Files.UploadError` object on failure.
    */
    public func upload(path path: String, mode: Files.WriteMode = .Add, autorename: Bool = false, clientModified: NSDate? = nil, mute: Bool = false, body: NSInputStream) -> DropboxUploadRequest<Files.FileMetadataSerializer, Files.UploadErrorSerializer> {
        let request = Files.CommitInfo(path: path, mode: mode, autorename: autorename, clientModified: clientModified, mute: mute)
        return DropboxUploadRequest(client: self.client, host: "content", route: "/files/upload", params: Files.CommitInfoSerializer().serialize(request), responseSerializer: Files.FileMetadataSerializer(), errorSerializer: Files.UploadErrorSerializer(), body: .Stream(body))
    }
    /**
        Append more data to an upload session. A single request should not upload more than 150 MB of file contents.

        - parameter sessionId: The upload session ID (returned by uploadSessionStart).
        - parameter offset: The amount of data that has been uploaded so far. We use this to make sure upload data isn't
        lost or duplicated in the event of a network error.
        - parameter body: The file to upload, as an NSData object

         - returns: Through the response callback, the caller will receive a `Void` object on success or a
        `Files.UploadSessionLookupError` object on failure.
    */
    public func uploadSessionAppend(sessionId sessionId: String, offset: UInt64, body: NSData) -> DropboxUploadRequest<VoidSerializer, Files.UploadSessionLookupErrorSerializer> {
        let request = Files.UploadSessionCursor(sessionId: sessionId, offset: offset)
        return DropboxUploadRequest(client: self.client, host: "content", route: "/files/upload_session/append", params: Files.UploadSessionCursorSerializer().serialize(request), responseSerializer: Serialization._VoidSerializer, errorSerializer: Files.UploadSessionLookupErrorSerializer(), body: .Data(body))
    }
    /**
        Append more data to an upload session. A single request should not upload more than 150 MB of file contents.

        - parameter sessionId: The upload session ID (returned by uploadSessionStart).
        - parameter offset: The amount of data that has been uploaded so far. We use this to make sure upload data isn't
        lost or duplicated in the event of a network error.
        - parameter body: The file to upload, as an NSURL object

         - returns: Through the response callback, the caller will receive a `Void` object on success or a
        `Files.UploadSessionLookupError` object on failure.
    */
    public func uploadSessionAppend(sessionId sessionId: String, offset: UInt64, body: NSURL) -> DropboxUploadRequest<VoidSerializer, Files.UploadSessionLookupErrorSerializer> {
        let request = Files.UploadSessionCursor(sessionId: sessionId, offset: offset)
        return DropboxUploadRequest(client: self.client, host: "content", route: "/files/upload_session/append", params: Files.UploadSessionCursorSerializer().serialize(request), responseSerializer: Serialization._VoidSerializer, errorSerializer: Files.UploadSessionLookupErrorSerializer(), body: .File(body))
    }
    /**
        Append more data to an upload session. A single request should not upload more than 150 MB of file contents.

        - parameter sessionId: The upload session ID (returned by uploadSessionStart).
        - parameter offset: The amount of data that has been uploaded so far. We use this to make sure upload data isn't
        lost or duplicated in the event of a network error.
        - parameter body: The file to upload, as an NSInputStream object

         - returns: Through the response callback, the caller will receive a `Void` object on success or a
        `Files.UploadSessionLookupError` object on failure.
    */
    public func uploadSessionAppend(sessionId sessionId: String, offset: UInt64, body: NSInputStream) -> DropboxUploadRequest<VoidSerializer, Files.UploadSessionLookupErrorSerializer> {
        let request = Files.UploadSessionCursor(sessionId: sessionId, offset: offset)
        return DropboxUploadRequest(client: self.client, host: "content", route: "/files/upload_session/append", params: Files.UploadSessionCursorSerializer().serialize(request), responseSerializer: Serialization._VoidSerializer, errorSerializer: Files.UploadSessionLookupErrorSerializer(), body: .Stream(body))
    }
    /**
        Finish an upload session and save the uploaded data to the given file path. A single request should not upload
        more than 150 MB of file contents.

        - parameter cursor: Contains the upload session ID and the offset.
        - parameter commit: Contains the path and other optional modifiers for the commit.
        - parameter body: The file to upload, as an NSData object

         - returns: Through the response callback, the caller will receive a `Files.FileMetadata` object on success or a
        `Files.UploadSessionFinishError` object on failure.
    */
    public func uploadSessionFinish(cursor cursor: Files.UploadSessionCursor, commit: Files.CommitInfo, body: NSData) -> DropboxUploadRequest<Files.FileMetadataSerializer, Files.UploadSessionFinishErrorSerializer> {
        let request = Files.UploadSessionFinishArg(cursor: cursor, commit: commit)
        return DropboxUploadRequest(client: self.client, host: "content", route: "/files/upload_session/finish", params: Files.UploadSessionFinishArgSerializer().serialize(request), responseSerializer: Files.FileMetadataSerializer(), errorSerializer: Files.UploadSessionFinishErrorSerializer(), body: .Data(body))
    }
    /**
        Finish an upload session and save the uploaded data to the given file path. A single request should not upload
        more than 150 MB of file contents.

        - parameter cursor: Contains the upload session ID and the offset.
        - parameter commit: Contains the path and other optional modifiers for the commit.
        - parameter body: The file to upload, as an NSURL object

         - returns: Through the response callback, the caller will receive a `Files.FileMetadata` object on success or a
        `Files.UploadSessionFinishError` object on failure.
    */
    public func uploadSessionFinish(cursor cursor: Files.UploadSessionCursor, commit: Files.CommitInfo, body: NSURL) -> DropboxUploadRequest<Files.FileMetadataSerializer, Files.UploadSessionFinishErrorSerializer> {
        let request = Files.UploadSessionFinishArg(cursor: cursor, commit: commit)
        return DropboxUploadRequest(client: self.client, host: "content", route: "/files/upload_session/finish", params: Files.UploadSessionFinishArgSerializer().serialize(request), responseSerializer: Files.FileMetadataSerializer(), errorSerializer: Files.UploadSessionFinishErrorSerializer(), body: .File(body))
    }
    /**
        Finish an upload session and save the uploaded data to the given file path. A single request should not upload
        more than 150 MB of file contents.

        - parameter cursor: Contains the upload session ID and the offset.
        - parameter commit: Contains the path and other optional modifiers for the commit.
        - parameter body: The file to upload, as an NSInputStream object

         - returns: Through the response callback, the caller will receive a `Files.FileMetadata` object on success or a
        `Files.UploadSessionFinishError` object on failure.
    */
    public func uploadSessionFinish(cursor cursor: Files.UploadSessionCursor, commit: Files.CommitInfo, body: NSInputStream) -> DropboxUploadRequest<Files.FileMetadataSerializer, Files.UploadSessionFinishErrorSerializer> {
        let request = Files.UploadSessionFinishArg(cursor: cursor, commit: commit)
        return DropboxUploadRequest(client: self.client, host: "content", route: "/files/upload_session/finish", params: Files.UploadSessionFinishArgSerializer().serialize(request), responseSerializer: Files.FileMetadataSerializer(), errorSerializer: Files.UploadSessionFinishErrorSerializer(), body: .Stream(body))
    }
    /**
        Upload sessions allow you to upload a single file using multiple requests. This call starts a new upload session
        with the given data.  You can then use uploadSessionAppend to add more data and uploadSessionFinish to save all
        the data to a file in Dropbox. A single request should not upload more than 150 MB of file contents.

        - parameter body: The file to upload, as an NSData object

         - returns: Through the response callback, the caller will receive a `Files.UploadSessionStartResult` object on
        success or a `Void` object on failure.
    */
    public func uploadSessionStart(body body: NSData) -> DropboxUploadRequest<Files.UploadSessionStartResultSerializer, VoidSerializer> {
        return DropboxUploadRequest(client: self.client, host: "content", route: "/files/upload_session/start", params: Serialization._VoidSerializer.serialize(), responseSerializer: Files.UploadSessionStartResultSerializer(), errorSerializer: Serialization._VoidSerializer, body: .Data(body))
    }
    /**
        Upload sessions allow you to upload a single file using multiple requests. This call starts a new upload session
        with the given data.  You can then use uploadSessionAppend to add more data and uploadSessionFinish to save all
        the data to a file in Dropbox. A single request should not upload more than 150 MB of file contents.

        - parameter body: The file to upload, as an NSURL object

         - returns: Through the response callback, the caller will receive a `Files.UploadSessionStartResult` object on
        success or a `Void` object on failure.
    */
    public func uploadSessionStart(body body: NSURL) -> DropboxUploadRequest<Files.UploadSessionStartResultSerializer, VoidSerializer> {
        return DropboxUploadRequest(client: self.client, host: "content", route: "/files/upload_session/start", params: Serialization._VoidSerializer.serialize(), responseSerializer: Files.UploadSessionStartResultSerializer(), errorSerializer: Serialization._VoidSerializer, body: .File(body))
    }
    /**
        Upload sessions allow you to upload a single file using multiple requests. This call starts a new upload session
        with the given data.  You can then use uploadSessionAppend to add more data and uploadSessionFinish to save all
        the data to a file in Dropbox. A single request should not upload more than 150 MB of file contents.

        - parameter body: The file to upload, as an NSInputStream object

         - returns: Through the response callback, the caller will receive a `Files.UploadSessionStartResult` object on
        success or a `Void` object on failure.
    */
    public func uploadSessionStart(body body: NSInputStream) -> DropboxUploadRequest<Files.UploadSessionStartResultSerializer, VoidSerializer> {
        return DropboxUploadRequest(client: self.client, host: "content", route: "/files/upload_session/start", params: Serialization._VoidSerializer.serialize(), responseSerializer: Files.UploadSessionStartResultSerializer(), errorSerializer: Serialization._VoidSerializer, body: .Stream(body))
    }
}