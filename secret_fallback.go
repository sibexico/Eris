package main

func withSecret(fn func()) {
	fn()
}
