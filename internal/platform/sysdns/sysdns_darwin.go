package sysdns

const needed = true

func enable(server string) (Snapshot, error) { return macResolver{execRun}.enable(server) }

func restore(s Snapshot) error { return macResolver{execRun}.restore(s) }
