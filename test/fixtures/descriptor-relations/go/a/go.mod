module example.com/app-a
go 1.21
require (
 example.com/shared v1.0.0
 example.com/indirect v1.0.0 // indirect
 example.com/replaced v1.0.0
 example.com/local v1.0.0
)
replace example.com/replaced => example.com/fork v2.0.0
replace example.com/local => ../local
