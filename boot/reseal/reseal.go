package reseal

type resealCalledFromKind int

const (
	resealCalledFromKindTask resealCalledFromKind = iota
	resealCalledFromKindEnsure
)

type ResealCalledFrom struct {
	kind  resealCalledFromKind
	extra any
}

func ResealCalledFromTask(taskKind string) ResealCalledFrom {
	return ResealCalledFrom{kind: resealCalledFromKindTask, extra: taskKind}
}

func ResealCalledFromEnsure(ensureName string) ResealCalledFrom {
	return ResealCalledFrom{kind: resealCalledFromKindEnsure, extra: ensureName}
}
