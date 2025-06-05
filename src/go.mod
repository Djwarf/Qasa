module github.com/qasa/main

go 1.23.8

require (
	github.com/qasa/network v0.0.0
	github.com/qasa/web v0.0.0
)

replace github.com/qasa/network => ./network
replace github.com/qasa/web => ./web 