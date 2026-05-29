.PHONY: refresh-catalogs refresh-eol refresh-fips refresh-pqc

refresh-eol:
	cd scripts/catalogs && go run ./refresh-eol.go

refresh-fips:
	cd scripts/catalogs && go run ./refresh-fips.go ./fips_gen.go

refresh-pqc:
	cd scripts/catalogs && go run ./refresh-pqc.go ./pqc_gen.go

refresh-catalogs: refresh-eol refresh-fips refresh-pqc
	@echo "Catalogs refreshed. Review the diff and commit."
