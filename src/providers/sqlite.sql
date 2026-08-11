CREATE TABLE IF NOT EXISTS "identity" (
	"id" TEXT PRIMARY KEY,
	"data" TEXT,
	"components" TEXT NOT NULL,
	"created_at" TEXT DEFAULT CURRENT_TIMESTAMP,
	"updated_at" TEXT DEFAULT CURRENT_TIMESTAMP
) STRICT;

CREATE TABLE IF NOT EXISTS "mv_identity_identification" (
	"component" TEXT NOT NULL,
	"identification" TEXT NOT NULL,
	"identity_id" TEXT NOT NULL,
	"updated_at" TEXT DEFAULT CURRENT_TIMESTAMP,
	PRIMARY KEY ("component", "identification"),
	FOREIGN KEY ("identity_id") REFERENCES "identity"("id") ON DELETE CASCADE
) STRICT;

CREATE TRIGGER IF NOT EXISTS trg_identity_insert AFTER INSERT ON "identity"
BEGIN
	INSERT INTO mv_identity_identification (component, identification, identity_id)
    SELECT		C.value->>'$.component' AS component, C.value->>'$.identification' AS identification, NEW.id
    	FROM	json_each(NEW.components) AS C
		WHERE	C.value->>'$.kind' = 'identification';
END;

CREATE TRIGGER IF NOT EXISTS trg_identity_update AFTER UPDATE ON "identity"
BEGIN
	DELETE FROM mv_identity_identification WHERE identity_id = NEW.id;
	INSERT INTO mv_identity_identification (component, identification, identity_id)
    SELECT		C.value->>'$.component' AS component, C.value->>'$.identification' AS identification, NEW.id
    	FROM	json_each(NEW.components) AS C
		WHERE	C.value->>'$.kind' = 'identification';
END;