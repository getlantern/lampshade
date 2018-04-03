package lampshade

type mockWriter struct {
	c chan []byte
}

func (m *mockWriter) Write(b []byte) (int, error) {
	m.c <- b
	return len(b), nil
}
