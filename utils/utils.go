package utils

// Convert array to map
func ArrayToMap(input []string) map[string]bool {
	output := map[string]bool{}
	for _, s := range input {
		output[s] = true
	}
	return output
}

func MapToArray(input map[string]bool) []string {
	output := []string{}
	for k := range input {
		output = append(output, k)
	}

	return output
}
