// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package migrations

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/NVIDIA/infra-controller/rest-api/db/pkg/db/model"
	"github.com/uptrace/bun"
)

func init() {
	Migrations.MustRegister(func(ctx context.Context, db *bun.DB) error {
		tx, terr := db.BeginTx(ctx, &sql.TxOptions{})
		if terr != nil {
			handlePanic(terr, "failed to begin transaction")
		}

		// create issuer table
		_, err := tx.NewCreateTable().Model((*model.Issuer)(nil)).IfNotExists().Exec(ctx)
		handleError(tx, err)

		// unique issuer_url across active rows
		_, err = tx.Exec("DROP INDEX IF EXISTS issuer_issuer_url_active_idx")
		handleError(tx, err)
		_, err = tx.Exec("CREATE UNIQUE INDEX issuer_issuer_url_active_idx ON issuer(issuer_url) WHERE deleted IS NULL")
		handleError(tx, err)

		terr = tx.Commit()
		if terr != nil {
			handlePanic(terr, "failed to commit transaction")
		}

		fmt.Print(" [up migration] Created 'issuer' table successfully. ")
		return nil
	}, func(ctx context.Context, db *bun.DB) error {
		fmt.Print(" [down migration] No action taken")
		return nil
	})
}
