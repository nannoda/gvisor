// automatically generated by stateify.

package gofer

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (l *dentryList) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.dentryList"
}

func (l *dentryList) StateFields() []string {
	return []string{
		"head",
		"tail",
	}
}

func (l *dentryList) beforeSave() {}

func (l *dentryList) StateSave(stateSinkObject state.Sink) {
	l.beforeSave()
	stateSinkObject.Save(0, &l.head)
	stateSinkObject.Save(1, &l.tail)
}

func (l *dentryList) afterLoad() {}

func (l *dentryList) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &l.head)
	stateSourceObject.Load(1, &l.tail)
}

func (e *dentryEntry) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.dentryEntry"
}

func (e *dentryEntry) StateFields() []string {
	return []string{
		"next",
		"prev",
	}
}

func (e *dentryEntry) beforeSave() {}

func (e *dentryEntry) StateSave(stateSinkObject state.Sink) {
	e.beforeSave()
	stateSinkObject.Save(0, &e.next)
	stateSinkObject.Save(1, &e.prev)
}

func (e *dentryEntry) afterLoad() {}

func (e *dentryEntry) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &e.next)
	stateSourceObject.Load(1, &e.prev)
}

func (fd *directoryFD) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.directoryFD"
}

func (fd *directoryFD) StateFields() []string {
	return []string{
		"fileDescription",
		"DirectoryFileDescriptionDefaultImpl",
		"off",
		"dirents",
	}
}

func (fd *directoryFD) beforeSave() {}

func (fd *directoryFD) StateSave(stateSinkObject state.Sink) {
	fd.beforeSave()
	stateSinkObject.Save(0, &fd.fileDescription)
	stateSinkObject.Save(1, &fd.DirectoryFileDescriptionDefaultImpl)
	stateSinkObject.Save(2, &fd.off)
	stateSinkObject.Save(3, &fd.dirents)
}

func (fd *directoryFD) afterLoad() {}

func (fd *directoryFD) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &fd.fileDescription)
	stateSourceObject.Load(1, &fd.DirectoryFileDescriptionDefaultImpl)
	stateSourceObject.Load(2, &fd.off)
	stateSourceObject.Load(3, &fd.dirents)
}

func (fstype *FilesystemType) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.FilesystemType"
}

func (fstype *FilesystemType) StateFields() []string {
	return []string{}
}

func (fstype *FilesystemType) beforeSave() {}

func (fstype *FilesystemType) StateSave(stateSinkObject state.Sink) {
	fstype.beforeSave()
}

func (fstype *FilesystemType) afterLoad() {}

func (fstype *FilesystemType) StateLoad(stateSourceObject state.Source) {
}

func (fs *filesystem) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.filesystem"
}

func (fs *filesystem) StateFields() []string {
	return []string{
		"vfsfs",
		"mfp",
		"opts",
		"iopts",
		"clock",
		"devMinor",
		"root",
		"cachedDentries",
		"cachedDentriesLen",
		"syncableDentries",
		"specialFileFDs",
		"lastIno",
		"savedDentryRW",
	}
}

func (fs *filesystem) beforeSave() {}

func (fs *filesystem) StateSave(stateSinkObject state.Sink) {
	fs.beforeSave()
	stateSinkObject.Save(0, &fs.vfsfs)
	stateSinkObject.Save(1, &fs.mfp)
	stateSinkObject.Save(2, &fs.opts)
	stateSinkObject.Save(3, &fs.iopts)
	stateSinkObject.Save(4, &fs.clock)
	stateSinkObject.Save(5, &fs.devMinor)
	stateSinkObject.Save(6, &fs.root)
	stateSinkObject.Save(7, &fs.cachedDentries)
	stateSinkObject.Save(8, &fs.cachedDentriesLen)
	stateSinkObject.Save(9, &fs.syncableDentries)
	stateSinkObject.Save(10, &fs.specialFileFDs)
	stateSinkObject.Save(11, &fs.lastIno)
	stateSinkObject.Save(12, &fs.savedDentryRW)
}

func (fs *filesystem) afterLoad() {}

func (fs *filesystem) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &fs.vfsfs)
	stateSourceObject.Load(1, &fs.mfp)
	stateSourceObject.Load(2, &fs.opts)
	stateSourceObject.Load(3, &fs.iopts)
	stateSourceObject.Load(4, &fs.clock)
	stateSourceObject.Load(5, &fs.devMinor)
	stateSourceObject.Load(6, &fs.root)
	stateSourceObject.Load(7, &fs.cachedDentries)
	stateSourceObject.Load(8, &fs.cachedDentriesLen)
	stateSourceObject.Load(9, &fs.syncableDentries)
	stateSourceObject.Load(10, &fs.specialFileFDs)
	stateSourceObject.Load(11, &fs.lastIno)
	stateSourceObject.Load(12, &fs.savedDentryRW)
}

func (f *filesystemOptions) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.filesystemOptions"
}

func (f *filesystemOptions) StateFields() []string {
	return []string{
		"fd",
		"aname",
		"interop",
		"dfltuid",
		"dfltgid",
		"msize",
		"version",
		"maxCachedDentries",
		"forcePageCache",
		"limitHostFDTranslation",
		"overlayfsStaleRead",
		"regularFilesUseSpecialFileFD",
	}
}

func (f *filesystemOptions) beforeSave() {}

func (f *filesystemOptions) StateSave(stateSinkObject state.Sink) {
	f.beforeSave()
	stateSinkObject.Save(0, &f.fd)
	stateSinkObject.Save(1, &f.aname)
	stateSinkObject.Save(2, &f.interop)
	stateSinkObject.Save(3, &f.dfltuid)
	stateSinkObject.Save(4, &f.dfltgid)
	stateSinkObject.Save(5, &f.msize)
	stateSinkObject.Save(6, &f.version)
	stateSinkObject.Save(7, &f.maxCachedDentries)
	stateSinkObject.Save(8, &f.forcePageCache)
	stateSinkObject.Save(9, &f.limitHostFDTranslation)
	stateSinkObject.Save(10, &f.overlayfsStaleRead)
	stateSinkObject.Save(11, &f.regularFilesUseSpecialFileFD)
}

func (f *filesystemOptions) afterLoad() {}

func (f *filesystemOptions) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &f.fd)
	stateSourceObject.Load(1, &f.aname)
	stateSourceObject.Load(2, &f.interop)
	stateSourceObject.Load(3, &f.dfltuid)
	stateSourceObject.Load(4, &f.dfltgid)
	stateSourceObject.Load(5, &f.msize)
	stateSourceObject.Load(6, &f.version)
	stateSourceObject.Load(7, &f.maxCachedDentries)
	stateSourceObject.Load(8, &f.forcePageCache)
	stateSourceObject.Load(9, &f.limitHostFDTranslation)
	stateSourceObject.Load(10, &f.overlayfsStaleRead)
	stateSourceObject.Load(11, &f.regularFilesUseSpecialFileFD)
}

func (i *InteropMode) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.InteropMode"
}

func (i *InteropMode) StateFields() []string {
	return nil
}

func (i *InternalFilesystemOptions) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.InternalFilesystemOptions"
}

func (i *InternalFilesystemOptions) StateFields() []string {
	return []string{
		"UniqueID",
		"LeakConnection",
		"OpenSocketsByConnecting",
	}
}

func (i *InternalFilesystemOptions) beforeSave() {}

func (i *InternalFilesystemOptions) StateSave(stateSinkObject state.Sink) {
	i.beforeSave()
	stateSinkObject.Save(0, &i.UniqueID)
	stateSinkObject.Save(1, &i.LeakConnection)
	stateSinkObject.Save(2, &i.OpenSocketsByConnecting)
}

func (i *InternalFilesystemOptions) afterLoad() {}

func (i *InternalFilesystemOptions) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &i.UniqueID)
	stateSourceObject.Load(1, &i.LeakConnection)
	stateSourceObject.Load(2, &i.OpenSocketsByConnecting)
}

func (d *dentry) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.dentry"
}

func (d *dentry) StateFields() []string {
	return []string{
		"vfsd",
		"refs",
		"fs",
		"parent",
		"name",
		"qidPath",
		"deleted",
		"cached",
		"dentryEntry",
		"children",
		"syntheticChildren",
		"dirents",
		"ino",
		"mode",
		"uid",
		"gid",
		"blockSize",
		"atime",
		"mtime",
		"ctime",
		"btime",
		"size",
		"atimeDirty",
		"mtimeDirty",
		"nlink",
		"mappings",
		"cache",
		"dirty",
		"pf",
		"haveTarget",
		"target",
		"endpoint",
		"pipe",
		"locks",
		"watches",
	}
}

func (d *dentry) StateSave(stateSinkObject state.Sink) {
	d.beforeSave()
	stateSinkObject.Save(0, &d.vfsd)
	stateSinkObject.Save(1, &d.refs)
	stateSinkObject.Save(2, &d.fs)
	stateSinkObject.Save(3, &d.parent)
	stateSinkObject.Save(4, &d.name)
	stateSinkObject.Save(5, &d.qidPath)
	stateSinkObject.Save(6, &d.deleted)
	stateSinkObject.Save(7, &d.cached)
	stateSinkObject.Save(8, &d.dentryEntry)
	stateSinkObject.Save(9, &d.children)
	stateSinkObject.Save(10, &d.syntheticChildren)
	stateSinkObject.Save(11, &d.dirents)
	stateSinkObject.Save(12, &d.ino)
	stateSinkObject.Save(13, &d.mode)
	stateSinkObject.Save(14, &d.uid)
	stateSinkObject.Save(15, &d.gid)
	stateSinkObject.Save(16, &d.blockSize)
	stateSinkObject.Save(17, &d.atime)
	stateSinkObject.Save(18, &d.mtime)
	stateSinkObject.Save(19, &d.ctime)
	stateSinkObject.Save(20, &d.btime)
	stateSinkObject.Save(21, &d.size)
	stateSinkObject.Save(22, &d.atimeDirty)
	stateSinkObject.Save(23, &d.mtimeDirty)
	stateSinkObject.Save(24, &d.nlink)
	stateSinkObject.Save(25, &d.mappings)
	stateSinkObject.Save(26, &d.cache)
	stateSinkObject.Save(27, &d.dirty)
	stateSinkObject.Save(28, &d.pf)
	stateSinkObject.Save(29, &d.haveTarget)
	stateSinkObject.Save(30, &d.target)
	stateSinkObject.Save(31, &d.endpoint)
	stateSinkObject.Save(32, &d.pipe)
	stateSinkObject.Save(33, &d.locks)
	stateSinkObject.Save(34, &d.watches)
}

func (d *dentry) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &d.vfsd)
	stateSourceObject.Load(1, &d.refs)
	stateSourceObject.Load(2, &d.fs)
	stateSourceObject.Load(3, &d.parent)
	stateSourceObject.Load(4, &d.name)
	stateSourceObject.Load(5, &d.qidPath)
	stateSourceObject.Load(6, &d.deleted)
	stateSourceObject.Load(7, &d.cached)
	stateSourceObject.Load(8, &d.dentryEntry)
	stateSourceObject.Load(9, &d.children)
	stateSourceObject.Load(10, &d.syntheticChildren)
	stateSourceObject.Load(11, &d.dirents)
	stateSourceObject.Load(12, &d.ino)
	stateSourceObject.Load(13, &d.mode)
	stateSourceObject.Load(14, &d.uid)
	stateSourceObject.Load(15, &d.gid)
	stateSourceObject.Load(16, &d.blockSize)
	stateSourceObject.Load(17, &d.atime)
	stateSourceObject.Load(18, &d.mtime)
	stateSourceObject.Load(19, &d.ctime)
	stateSourceObject.Load(20, &d.btime)
	stateSourceObject.Load(21, &d.size)
	stateSourceObject.Load(22, &d.atimeDirty)
	stateSourceObject.Load(23, &d.mtimeDirty)
	stateSourceObject.Load(24, &d.nlink)
	stateSourceObject.Load(25, &d.mappings)
	stateSourceObject.Load(26, &d.cache)
	stateSourceObject.Load(27, &d.dirty)
	stateSourceObject.Load(28, &d.pf)
	stateSourceObject.Load(29, &d.haveTarget)
	stateSourceObject.Load(30, &d.target)
	stateSourceObject.Load(31, &d.endpoint)
	stateSourceObject.Load(32, &d.pipe)
	stateSourceObject.Load(33, &d.locks)
	stateSourceObject.Load(34, &d.watches)
	stateSourceObject.AfterLoad(d.afterLoad)
}

func (fd *fileDescription) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.fileDescription"
}

func (fd *fileDescription) StateFields() []string {
	return []string{
		"vfsfd",
		"FileDescriptionDefaultImpl",
		"LockFD",
	}
}

func (fd *fileDescription) beforeSave() {}

func (fd *fileDescription) StateSave(stateSinkObject state.Sink) {
	fd.beforeSave()
	stateSinkObject.Save(0, &fd.vfsfd)
	stateSinkObject.Save(1, &fd.FileDescriptionDefaultImpl)
	stateSinkObject.Save(2, &fd.LockFD)
}

func (fd *fileDescription) afterLoad() {}

func (fd *fileDescription) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &fd.vfsfd)
	stateSourceObject.Load(1, &fd.FileDescriptionDefaultImpl)
	stateSourceObject.Load(2, &fd.LockFD)
}

func (fd *regularFileFD) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.regularFileFD"
}

func (fd *regularFileFD) StateFields() []string {
	return []string{
		"fileDescription",
		"off",
	}
}

func (fd *regularFileFD) beforeSave() {}

func (fd *regularFileFD) StateSave(stateSinkObject state.Sink) {
	fd.beforeSave()
	stateSinkObject.Save(0, &fd.fileDescription)
	stateSinkObject.Save(1, &fd.off)
}

func (fd *regularFileFD) afterLoad() {}

func (fd *regularFileFD) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &fd.fileDescription)
	stateSourceObject.Load(1, &fd.off)
}

func (d *dentryPlatformFile) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.dentryPlatformFile"
}

func (d *dentryPlatformFile) StateFields() []string {
	return []string{
		"dentry",
		"fdRefs",
		"hostFileMapper",
	}
}

func (d *dentryPlatformFile) beforeSave() {}

func (d *dentryPlatformFile) StateSave(stateSinkObject state.Sink) {
	d.beforeSave()
	stateSinkObject.Save(0, &d.dentry)
	stateSinkObject.Save(1, &d.fdRefs)
	stateSinkObject.Save(2, &d.hostFileMapper)
}

func (d *dentryPlatformFile) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &d.dentry)
	stateSourceObject.Load(1, &d.fdRefs)
	stateSourceObject.Load(2, &d.hostFileMapper)
	stateSourceObject.AfterLoad(d.afterLoad)
}

func (s *savedDentryRW) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.savedDentryRW"
}

func (s *savedDentryRW) StateFields() []string {
	return []string{
		"read",
		"write",
	}
}

func (s *savedDentryRW) beforeSave() {}

func (s *savedDentryRW) StateSave(stateSinkObject state.Sink) {
	s.beforeSave()
	stateSinkObject.Save(0, &s.read)
	stateSinkObject.Save(1, &s.write)
}

func (s *savedDentryRW) afterLoad() {}

func (s *savedDentryRW) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &s.read)
	stateSourceObject.Load(1, &s.write)
}

func (e *endpoint) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.endpoint"
}

func (e *endpoint) StateFields() []string {
	return []string{
		"dentry",
		"path",
	}
}

func (e *endpoint) beforeSave() {}

func (e *endpoint) StateSave(stateSinkObject state.Sink) {
	e.beforeSave()
	stateSinkObject.Save(0, &e.dentry)
	stateSinkObject.Save(1, &e.path)
}

func (e *endpoint) afterLoad() {}

func (e *endpoint) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &e.dentry)
	stateSourceObject.Load(1, &e.path)
}

func (fd *specialFileFD) StateTypeName() string {
	return "pkg/sentry/fsimpl/gofer.specialFileFD"
}

func (fd *specialFileFD) StateFields() []string {
	return []string{
		"fileDescription",
		"isRegularFile",
		"seekable",
		"queue",
		"off",
		"haveBuf",
		"buf",
	}
}

func (fd *specialFileFD) beforeSave() {}

func (fd *specialFileFD) StateSave(stateSinkObject state.Sink) {
	fd.beforeSave()
	stateSinkObject.Save(0, &fd.fileDescription)
	stateSinkObject.Save(1, &fd.isRegularFile)
	stateSinkObject.Save(2, &fd.seekable)
	stateSinkObject.Save(3, &fd.queue)
	stateSinkObject.Save(4, &fd.off)
	stateSinkObject.Save(5, &fd.haveBuf)
	stateSinkObject.Save(6, &fd.buf)
}

func (fd *specialFileFD) StateLoad(stateSourceObject state.Source) {
	stateSourceObject.Load(0, &fd.fileDescription)
	stateSourceObject.Load(1, &fd.isRegularFile)
	stateSourceObject.Load(2, &fd.seekable)
	stateSourceObject.Load(3, &fd.queue)
	stateSourceObject.Load(4, &fd.off)
	stateSourceObject.Load(5, &fd.haveBuf)
	stateSourceObject.Load(6, &fd.buf)
	stateSourceObject.AfterLoad(fd.afterLoad)
}

func init() {
	state.Register((*dentryList)(nil))
	state.Register((*dentryEntry)(nil))
	state.Register((*directoryFD)(nil))
	state.Register((*FilesystemType)(nil))
	state.Register((*filesystem)(nil))
	state.Register((*filesystemOptions)(nil))
	state.Register((*InteropMode)(nil))
	state.Register((*InternalFilesystemOptions)(nil))
	state.Register((*dentry)(nil))
	state.Register((*fileDescription)(nil))
	state.Register((*regularFileFD)(nil))
	state.Register((*dentryPlatformFile)(nil))
	state.Register((*savedDentryRW)(nil))
	state.Register((*endpoint)(nil))
	state.Register((*specialFileFD)(nil))
}
