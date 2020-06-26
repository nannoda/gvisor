// automatically generated by stateify.

package vfs

import (
	"gvisor.dev/gvisor/pkg/state"
)

func (x *Dentry) StateTypeName() string {
	return "pkg/sentry/vfs.Dentry"
}

func (x *Dentry) StateFields() []string {
	return []string{
		"dead",
		"mounts",
		"impl",
	}
}

func (x *Dentry) beforeSave() {}

func (x *Dentry) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.dead)
	m.Save(1, &x.mounts)
	m.Save(2, &x.impl)
}

func (x *Dentry) afterLoad() {}

func (x *Dentry) StateLoad(m state.Source) {
	m.Load(0, &x.dead)
	m.Load(1, &x.mounts)
	m.Load(2, &x.impl)
}

func (x *registeredDevice) StateTypeName() string {
	return "pkg/sentry/vfs.registeredDevice"
}

func (x *registeredDevice) StateFields() []string {
	return []string{
		"dev",
		"opts",
	}
}

func (x *registeredDevice) beforeSave() {}

func (x *registeredDevice) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.dev)
	m.Save(1, &x.opts)
}

func (x *registeredDevice) afterLoad() {}

func (x *registeredDevice) StateLoad(m state.Source) {
	m.Load(0, &x.dev)
	m.Load(1, &x.opts)
}

func (x *RegisterDeviceOptions) StateTypeName() string {
	return "pkg/sentry/vfs.RegisterDeviceOptions"
}

func (x *RegisterDeviceOptions) StateFields() []string {
	return []string{
		"GroupName",
	}
}

func (x *RegisterDeviceOptions) beforeSave() {}

func (x *RegisterDeviceOptions) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.GroupName)
}

func (x *RegisterDeviceOptions) afterLoad() {}

func (x *RegisterDeviceOptions) StateLoad(m state.Source) {
	m.Load(0, &x.GroupName)
}

func (x *epollInterestList) StateTypeName() string {
	return "pkg/sentry/vfs.epollInterestList"
}

func (x *epollInterestList) StateFields() []string {
	return []string{
		"head",
		"tail",
	}
}

func (x *epollInterestList) beforeSave() {}

func (x *epollInterestList) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.head)
	m.Save(1, &x.tail)
}

func (x *epollInterestList) afterLoad() {}

func (x *epollInterestList) StateLoad(m state.Source) {
	m.Load(0, &x.head)
	m.Load(1, &x.tail)
}

func (x *epollInterestEntry) StateTypeName() string {
	return "pkg/sentry/vfs.epollInterestEntry"
}

func (x *epollInterestEntry) StateFields() []string {
	return []string{
		"next",
		"prev",
	}
}

func (x *epollInterestEntry) beforeSave() {}

func (x *epollInterestEntry) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.next)
	m.Save(1, &x.prev)
}

func (x *epollInterestEntry) afterLoad() {}

func (x *epollInterestEntry) StateLoad(m state.Source) {
	m.Load(0, &x.next)
	m.Load(1, &x.prev)
}

func (x *eventList) StateTypeName() string {
	return "pkg/sentry/vfs.eventList"
}

func (x *eventList) StateFields() []string {
	return []string{
		"head",
		"tail",
	}
}

func (x *eventList) beforeSave() {}

func (x *eventList) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.head)
	m.Save(1, &x.tail)
}

func (x *eventList) afterLoad() {}

func (x *eventList) StateLoad(m state.Source) {
	m.Load(0, &x.head)
	m.Load(1, &x.tail)
}

func (x *eventEntry) StateTypeName() string {
	return "pkg/sentry/vfs.eventEntry"
}

func (x *eventEntry) StateFields() []string {
	return []string{
		"next",
		"prev",
	}
}

func (x *eventEntry) beforeSave() {}

func (x *eventEntry) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.next)
	m.Save(1, &x.prev)
}

func (x *eventEntry) afterLoad() {}

func (x *eventEntry) StateLoad(m state.Source) {
	m.Load(0, &x.next)
	m.Load(1, &x.prev)
}

func (x *Filesystem) StateTypeName() string {
	return "pkg/sentry/vfs.Filesystem"
}

func (x *Filesystem) StateFields() []string {
	return []string{
		"refs",
		"vfs",
		"fsType",
		"impl",
	}
}

func (x *Filesystem) beforeSave() {}

func (x *Filesystem) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.refs)
	m.Save(1, &x.vfs)
	m.Save(2, &x.fsType)
	m.Save(3, &x.impl)
}

func (x *Filesystem) afterLoad() {}

func (x *Filesystem) StateLoad(m state.Source) {
	m.Load(0, &x.refs)
	m.Load(1, &x.vfs)
	m.Load(2, &x.fsType)
	m.Load(3, &x.impl)
}

func (x *registeredFilesystemType) StateTypeName() string {
	return "pkg/sentry/vfs.registeredFilesystemType"
}

func (x *registeredFilesystemType) StateFields() []string {
	return []string{
		"fsType",
		"opts",
	}
}

func (x *registeredFilesystemType) beforeSave() {}

func (x *registeredFilesystemType) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.fsType)
	m.Save(1, &x.opts)
}

func (x *registeredFilesystemType) afterLoad() {}

func (x *registeredFilesystemType) StateLoad(m state.Source) {
	m.Load(0, &x.fsType)
	m.Load(1, &x.opts)
}

func (x *Inotify) StateTypeName() string {
	return "pkg/sentry/vfs.Inotify"
}

func (x *Inotify) StateFields() []string {
	return []string{
		"vfsfd",
		"FileDescriptionDefaultImpl",
		"DentryMetadataFileDescriptionImpl",
		"NoLockFD",
		"id",
		"events",
		"scratch",
		"nextWatchMinusOne",
		"watches",
	}
}

func (x *Inotify) beforeSave() {}

func (x *Inotify) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.vfsfd)
	m.Save(1, &x.FileDescriptionDefaultImpl)
	m.Save(2, &x.DentryMetadataFileDescriptionImpl)
	m.Save(3, &x.NoLockFD)
	m.Save(4, &x.id)
	m.Save(5, &x.events)
	m.Save(6, &x.scratch)
	m.Save(7, &x.nextWatchMinusOne)
	m.Save(8, &x.watches)
}

func (x *Inotify) afterLoad() {}

func (x *Inotify) StateLoad(m state.Source) {
	m.Load(0, &x.vfsfd)
	m.Load(1, &x.FileDescriptionDefaultImpl)
	m.Load(2, &x.DentryMetadataFileDescriptionImpl)
	m.Load(3, &x.NoLockFD)
	m.Load(4, &x.id)
	m.Load(5, &x.events)
	m.Load(6, &x.scratch)
	m.Load(7, &x.nextWatchMinusOne)
	m.Load(8, &x.watches)
}

func (x *Watches) StateTypeName() string {
	return "pkg/sentry/vfs.Watches"
}

func (x *Watches) StateFields() []string {
	return []string{
		"ws",
	}
}

func (x *Watches) beforeSave() {}

func (x *Watches) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.ws)
}

func (x *Watches) afterLoad() {}

func (x *Watches) StateLoad(m state.Source) {
	m.Load(0, &x.ws)
}

func (x *Watch) StateTypeName() string {
	return "pkg/sentry/vfs.Watch"
}

func (x *Watch) StateFields() []string {
	return []string{
		"owner",
		"wd",
		"target",
		"mask",
		"expired",
	}
}

func (x *Watch) beforeSave() {}

func (x *Watch) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.owner)
	m.Save(1, &x.wd)
	m.Save(2, &x.target)
	m.Save(3, &x.mask)
	m.Save(4, &x.expired)
}

func (x *Watch) afterLoad() {}

func (x *Watch) StateLoad(m state.Source) {
	m.Load(0, &x.owner)
	m.Load(1, &x.wd)
	m.Load(2, &x.target)
	m.Load(3, &x.mask)
	m.Load(4, &x.expired)
}

func (x *Event) StateTypeName() string {
	return "pkg/sentry/vfs.Event"
}

func (x *Event) StateFields() []string {
	return []string{
		"eventEntry",
		"wd",
		"mask",
		"cookie",
		"len",
		"name",
	}
}

func (x *Event) beforeSave() {}

func (x *Event) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.eventEntry)
	m.Save(1, &x.wd)
	m.Save(2, &x.mask)
	m.Save(3, &x.cookie)
	m.Save(4, &x.len)
	m.Save(5, &x.name)
}

func (x *Event) afterLoad() {}

func (x *Event) StateLoad(m state.Source) {
	m.Load(0, &x.eventEntry)
	m.Load(1, &x.wd)
	m.Load(2, &x.mask)
	m.Load(3, &x.cookie)
	m.Load(4, &x.len)
	m.Load(5, &x.name)
}

func (x *Mount) StateTypeName() string {
	return "pkg/sentry/vfs.Mount"
}

func (x *Mount) StateFields() []string {
	return []string{
		"vfs",
		"fs",
		"root",
		"ID",
		"Flags",
		"key",
		"ns",
		"refs",
		"children",
		"umounted",
		"writers",
	}
}

func (x *Mount) beforeSave() {}

func (x *Mount) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.vfs)
	m.Save(1, &x.fs)
	m.Save(2, &x.root)
	m.Save(3, &x.ID)
	m.Save(4, &x.Flags)
	m.Save(5, &x.key)
	m.Save(6, &x.ns)
	m.Save(7, &x.refs)
	m.Save(8, &x.children)
	m.Save(9, &x.umounted)
	m.Save(10, &x.writers)
}

func (x *Mount) afterLoad() {}

func (x *Mount) StateLoad(m state.Source) {
	m.Load(0, &x.vfs)
	m.Load(1, &x.fs)
	m.Load(2, &x.root)
	m.Load(3, &x.ID)
	m.Load(4, &x.Flags)
	m.Load(5, &x.key)
	m.Load(6, &x.ns)
	m.Load(7, &x.refs)
	m.Load(8, &x.children)
	m.Load(9, &x.umounted)
	m.Load(10, &x.writers)
}

func (x *MountNamespace) StateTypeName() string {
	return "pkg/sentry/vfs.MountNamespace"
}

func (x *MountNamespace) StateFields() []string {
	return []string{
		"Owner",
		"root",
		"refs",
		"mountpoints",
	}
}

func (x *MountNamespace) beforeSave() {}

func (x *MountNamespace) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.Owner)
	m.Save(1, &x.root)
	m.Save(2, &x.refs)
	m.Save(3, &x.mountpoints)
}

func (x *MountNamespace) afterLoad() {}

func (x *MountNamespace) StateLoad(m state.Source) {
	m.Load(0, &x.Owner)
	m.Load(1, &x.root)
	m.Load(2, &x.refs)
	m.Load(3, &x.mountpoints)
}

func (x *VirtualFilesystem) StateTypeName() string {
	return "pkg/sentry/vfs.VirtualFilesystem"
}

func (x *VirtualFilesystem) StateFields() []string {
	return []string{
		"mounts",
		"mountpoints",
		"lastMountID",
		"anonMount",
		"devices",
		"anonBlockDevMinorNext",
		"anonBlockDevMinor",
		"fsTypes",
		"filesystems",
	}
}

func (x *VirtualFilesystem) beforeSave() {}

func (x *VirtualFilesystem) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.mounts)
	m.Save(1, &x.mountpoints)
	m.Save(2, &x.lastMountID)
	m.Save(3, &x.anonMount)
	m.Save(4, &x.devices)
	m.Save(5, &x.anonBlockDevMinorNext)
	m.Save(6, &x.anonBlockDevMinor)
	m.Save(7, &x.fsTypes)
	m.Save(8, &x.filesystems)
}

func (x *VirtualFilesystem) afterLoad() {}

func (x *VirtualFilesystem) StateLoad(m state.Source) {
	m.Load(0, &x.mounts)
	m.Load(1, &x.mountpoints)
	m.Load(2, &x.lastMountID)
	m.Load(3, &x.anonMount)
	m.Load(4, &x.devices)
	m.Load(5, &x.anonBlockDevMinorNext)
	m.Load(6, &x.anonBlockDevMinor)
	m.Load(7, &x.fsTypes)
	m.Load(8, &x.filesystems)
}

func (x *VirtualDentry) StateTypeName() string {
	return "pkg/sentry/vfs.VirtualDentry"
}

func (x *VirtualDentry) StateFields() []string {
	return []string{
		"mount",
		"dentry",
	}
}

func (x *VirtualDentry) beforeSave() {}

func (x *VirtualDentry) StateSave(m state.Sink) {
	x.beforeSave()
	m.Save(0, &x.mount)
	m.Save(1, &x.dentry)
}

func (x *VirtualDentry) afterLoad() {}

func (x *VirtualDentry) StateLoad(m state.Source) {
	m.Load(0, &x.mount)
	m.Load(1, &x.dentry)
}

func init() {
	state.Register((*Dentry)(nil))
	state.Register((*registeredDevice)(nil))
	state.Register((*RegisterDeviceOptions)(nil))
	state.Register((*epollInterestList)(nil))
	state.Register((*epollInterestEntry)(nil))
	state.Register((*eventList)(nil))
	state.Register((*eventEntry)(nil))
	state.Register((*Filesystem)(nil))
	state.Register((*registeredFilesystemType)(nil))
	state.Register((*Inotify)(nil))
	state.Register((*Watches)(nil))
	state.Register((*Watch)(nil))
	state.Register((*Event)(nil))
	state.Register((*Mount)(nil))
	state.Register((*MountNamespace)(nil))
	state.Register((*VirtualFilesystem)(nil))
	state.Register((*VirtualDentry)(nil))
}
