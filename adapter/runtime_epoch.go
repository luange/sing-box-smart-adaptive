package adapter

type RuntimeEpochLifecycle interface {
	OnRuntimeEpochPublish()
	OnRuntimeEpochRetire()
}

type RuntimeEpochLease interface {
	Release()
}
