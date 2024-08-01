package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-playground/validator/v10"
)

// TODO: add generics here
func decodeWithValidation(
	r *http.Request,
	v any,
	validate *validator.Validate,
) error {
	err := json.NewDecoder(r.Body).Decode(v)
	if err != nil {
		return errors.New("invalid JSON body")
	}
	err = validate.Struct(v)
	return err
}

func respondWithJson(w http.ResponseWriter, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		respondWithServerError(w)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func respondWithServerError(w http.ResponseWriter) {
	respondWithError(w, errors.New("internal server error"), http.StatusInternalServerError)
}

func respondWithUnauthorized(w http.ResponseWriter) {
	respondWithErrorMessage(w, "Unauthorized", http.StatusUnauthorized)
}

func respondWithForbidden(w http.ResponseWriter) {
	respondWithErrorMessage(w, "Forbidden", http.StatusForbidden)
}

func respondWithError(w http.ResponseWriter, err error, status int) {
	http.Error(w, err.Error(), status)
}

func respondWithErrorMessage(w http.ResponseWriter, message string, status int) {
	http.Error(w, message, status)
}

func respondWithNoContent(w http.ResponseWriter) {
	w.WriteHeader(http.StatusNoContent)
}
