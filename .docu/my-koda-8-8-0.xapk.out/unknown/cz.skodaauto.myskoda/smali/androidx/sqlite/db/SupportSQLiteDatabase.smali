.class public interface abstract Landroidx/sqlite/db/SupportSQLiteDatabase;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# virtual methods
.method public abstract beginTransaction()V
.end method

.method public abstract beginTransactionNonExclusive()V
.end method

.method public beginTransactionReadOnly()V
    .locals 0

    .line 1
    invoke-interface {p0}, Landroidx/sqlite/db/SupportSQLiteDatabase;->beginTransaction()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public abstract beginTransactionWithListener(Landroid/database/sqlite/SQLiteTransactionListener;)V
.end method

.method public abstract compileStatement(Ljava/lang/String;)Landroidx/sqlite/db/SupportSQLiteStatement;
.end method

.method public abstract disableWriteAheadLogging()V
.end method

.method public abstract enableWriteAheadLogging()Z
.end method

.method public abstract endTransaction()V
.end method

.method public abstract execSQL(Ljava/lang/String;)V
.end method

.method public abstract execSQL(Ljava/lang/String;[Ljava/lang/Object;)V
.end method

.method public abstract inTransaction()Z
.end method

.method public abstract isOpen()Z
.end method

.method public abstract isWriteAheadLoggingEnabled()Z
.end method

.method public abstract query(Landroidx/sqlite/db/SupportSQLiteQuery;)Landroid/database/Cursor;
.end method

.method public abstract setTransactionSuccessful()V
.end method

.method public abstract update(Ljava/lang/String;ILandroid/content/ContentValues;Ljava/lang/String;[Ljava/lang/Object;)I
.end method
