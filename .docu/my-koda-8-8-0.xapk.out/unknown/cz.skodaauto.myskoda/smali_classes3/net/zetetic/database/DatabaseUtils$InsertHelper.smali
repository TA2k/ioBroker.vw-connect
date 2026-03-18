.class public Lnet/zetetic/database/DatabaseUtils$InsertHelper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lnet/zetetic/database/DatabaseUtils;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "InsertHelper"
.end annotation

.annotation runtime Ljava/lang/Deprecated;
.end annotation


# static fields
.field public static final TABLE_INFO_PRAGMA_COLUMNNAME_INDEX:I = 0x1

.field public static final TABLE_INFO_PRAGMA_DEFAULT_INDEX:I = 0x4


# instance fields
.field private mColumns:Ljava/util/HashMap;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/HashMap<",
            "Ljava/lang/String;",
            "Ljava/lang/Integer;",
            ">;"
        }
    .end annotation
.end field

.field private final mDb:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

.field private mInsertSQL:Ljava/lang/String;

.field private mInsertStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

.field private mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

.field private mReplaceStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

.field private final mTableName:Ljava/lang/String;


# direct methods
.method public constructor <init>(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;Ljava/lang/String;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mInsertSQL:Ljava/lang/String;

    .line 6
    .line 7
    iput-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mInsertStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 8
    .line 9
    iput-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mReplaceStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 10
    .line 11
    iput-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 12
    .line 13
    iput-object p1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mDb:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 14
    .line 15
    iput-object p2, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mTableName:Ljava/lang/String;

    .line 16
    .line 17
    return-void
.end method

.method private buildSQL()V
    .locals 11

    .line 1
    const-string v0, "\'"

    .line 2
    .line 3
    const-string v1, ")"

    .line 4
    .line 5
    const-string v2, "PRAGMA table_info("

    .line 6
    .line 7
    new-instance v3, Ljava/lang/StringBuilder;

    .line 8
    .line 9
    const/16 v4, 0x80

    .line 10
    .line 11
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 12
    .line 13
    .line 14
    const-string v5, "INSERT INTO "

    .line 15
    .line 16
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    iget-object v5, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mTableName:Ljava/lang/String;

    .line 20
    .line 21
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    const-string v5, " ("

    .line 25
    .line 26
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 27
    .line 28
    .line 29
    new-instance v5, Ljava/lang/StringBuilder;

    .line 30
    .line 31
    invoke-direct {v5, v4}, Ljava/lang/StringBuilder;-><init>(I)V

    .line 32
    .line 33
    .line 34
    const-string v4, "VALUES ("

    .line 35
    .line 36
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const/4 v4, 0x0

    .line 40
    :try_start_0
    iget-object v6, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mDb:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 41
    .line 42
    new-instance v7, Ljava/lang/StringBuilder;

    .line 43
    .line 44
    invoke-direct {v7, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    iget-object v2, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mTableName:Ljava/lang/String;

    .line 48
    .line 49
    invoke-virtual {v7, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v7, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 56
    .line 57
    .line 58
    move-result-object v2

    .line 59
    invoke-virtual {v6, v2, v4}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->rawQuery(Ljava/lang/String;[Ljava/lang/String;)Landroid/database/Cursor;

    .line 60
    .line 61
    .line 62
    move-result-object v4

    .line 63
    new-instance v2, Ljava/util/HashMap;

    .line 64
    .line 65
    invoke-interface {v4}, Landroid/database/Cursor;->getCount()I

    .line 66
    .line 67
    .line 68
    move-result v6

    .line 69
    invoke-direct {v2, v6}, Ljava/util/HashMap;-><init>(I)V

    .line 70
    .line 71
    .line 72
    iput-object v2, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mColumns:Ljava/util/HashMap;

    .line 73
    .line 74
    const/4 v2, 0x1

    .line 75
    move v6, v2

    .line 76
    :goto_0
    invoke-interface {v4}, Landroid/database/Cursor;->moveToNext()Z

    .line 77
    .line 78
    .line 79
    move-result v7

    .line 80
    if-eqz v7, :cond_3

    .line 81
    .line 82
    invoke-interface {v4, v2}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v7

    .line 86
    const/4 v8, 0x4

    .line 87
    invoke-interface {v4, v8}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object v8

    .line 91
    iget-object v9, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mColumns:Ljava/util/HashMap;

    .line 92
    .line 93
    invoke-static {v6}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 94
    .line 95
    .line 96
    move-result-object v10

    .line 97
    invoke-virtual {v9, v7, v10}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 101
    .line 102
    .line 103
    invoke-virtual {v3, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 104
    .line 105
    .line 106
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 107
    .line 108
    .line 109
    if-nez v8, :cond_0

    .line 110
    .line 111
    const-string v7, "?"

    .line 112
    .line 113
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 114
    .line 115
    .line 116
    goto :goto_1

    .line 117
    :catchall_0
    move-exception p0

    .line 118
    goto :goto_3

    .line 119
    :cond_0
    const-string v7, "COALESCE(?, "

    .line 120
    .line 121
    invoke-virtual {v5, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 122
    .line 123
    .line 124
    invoke-virtual {v5, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 125
    .line 126
    .line 127
    invoke-virtual {v5, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 128
    .line 129
    .line 130
    :goto_1
    invoke-interface {v4}, Landroid/database/Cursor;->getCount()I

    .line 131
    .line 132
    .line 133
    move-result v7
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 134
    const-string v8, ", "

    .line 135
    .line 136
    if-ne v6, v7, :cond_1

    .line 137
    .line 138
    :try_start_1
    const-string v7, ") "

    .line 139
    .line 140
    goto :goto_2

    .line 141
    :cond_1
    move-object v7, v8

    .line 142
    :goto_2
    invoke-virtual {v3, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 143
    .line 144
    .line 145
    invoke-interface {v4}, Landroid/database/Cursor;->getCount()I

    .line 146
    .line 147
    .line 148
    move-result v7

    .line 149
    if-ne v6, v7, :cond_2

    .line 150
    .line 151
    const-string v8, ");"

    .line 152
    .line 153
    :cond_2
    invoke-virtual {v5, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 154
    .line 155
    .line 156
    add-int/lit8 v6, v6, 0x1

    .line 157
    .line 158
    goto :goto_0

    .line 159
    :cond_3
    invoke-interface {v4}, Landroid/database/Cursor;->close()V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v3, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/CharSequence;)Ljava/lang/StringBuilder;

    .line 163
    .line 164
    .line 165
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object v0

    .line 169
    iput-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mInsertSQL:Ljava/lang/String;

    .line 170
    .line 171
    return-void

    .line 172
    :goto_3
    if-eqz v4, :cond_4

    .line 173
    .line 174
    invoke-interface {v4}, Landroid/database/Cursor;->close()V

    .line 175
    .line 176
    .line 177
    :cond_4
    throw p0
.end method

.method private getStatement(Z)Lnet/zetetic/database/sqlcipher/SQLiteStatement;
    .locals 2

    .line 1
    if-eqz p1, :cond_2

    .line 2
    .line 3
    iget-object p1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mReplaceStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 4
    .line 5
    if-nez p1, :cond_1

    .line 6
    .line 7
    iget-object p1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mInsertSQL:Ljava/lang/String;

    .line 8
    .line 9
    if-nez p1, :cond_0

    .line 10
    .line 11
    invoke-direct {p0}, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->buildSQL()V

    .line 12
    .line 13
    .line 14
    :cond_0
    new-instance p1, Ljava/lang/StringBuilder;

    .line 15
    .line 16
    const-string v0, "INSERT OR REPLACE"

    .line 17
    .line 18
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 19
    .line 20
    .line 21
    iget-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mInsertSQL:Ljava/lang/String;

    .line 22
    .line 23
    const/4 v1, 0x6

    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    invoke-virtual {p1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    iget-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mDb:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 36
    .line 37
    invoke-virtual {v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    iput-object p1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mReplaceStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 42
    .line 43
    :cond_1
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mReplaceStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 44
    .line 45
    return-object p0

    .line 46
    :cond_2
    iget-object p1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mInsertStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 47
    .line 48
    if-nez p1, :cond_4

    .line 49
    .line 50
    iget-object p1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mInsertSQL:Ljava/lang/String;

    .line 51
    .line 52
    if-nez p1, :cond_3

    .line 53
    .line 54
    invoke-direct {p0}, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->buildSQL()V

    .line 55
    .line 56
    .line 57
    :cond_3
    iget-object p1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mDb:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 58
    .line 59
    iget-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mInsertSQL:Ljava/lang/String;

    .line 60
    .line 61
    invoke-virtual {p1, v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->compileStatement(Ljava/lang/String;)Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    iput-object p1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mInsertStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 66
    .line 67
    :cond_4
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mInsertStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 68
    .line 69
    return-object p0
.end method

.method private insertInternal(Landroid/content/ContentValues;Z)J
    .locals 3

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mDb:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 2
    .line 3
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->beginTransactionNonExclusive()V

    .line 4
    .line 5
    .line 6
    :try_start_0
    invoke-direct {p0, p2}, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->getStatement(Z)Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 7
    .line 8
    .line 9
    move-result-object p2

    .line 10
    invoke-virtual {p2}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->clearBindings()V

    .line 11
    .line 12
    .line 13
    invoke-virtual {p1}, Landroid/content/ContentValues;->valueSet()Ljava/util/Set;

    .line 14
    .line 15
    .line 16
    move-result-object v0

    .line 17
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    if-eqz v1, :cond_0

    .line 26
    .line 27
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v1

    .line 31
    check-cast v1, Ljava/util/Map$Entry;

    .line 32
    .line 33
    invoke-interface {v1}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v2

    .line 37
    check-cast v2, Ljava/lang/String;

    .line 38
    .line 39
    invoke-virtual {p0, v2}, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->getColumnIndex(Ljava/lang/String;)I

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    invoke-interface {v1}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v1

    .line 47
    invoke-static {p2, v2, v1}, Lnet/zetetic/database/DatabaseUtils;->bindObjectToProgram(Lnet/zetetic/database/sqlcipher/SQLiteProgram;ILjava/lang/Object;)V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :catchall_0
    move-exception p1

    .line 52
    goto :goto_2

    .line 53
    :catch_0
    move-exception p2

    .line 54
    goto :goto_1

    .line 55
    :cond_0
    invoke-virtual {p2}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;->executeInsert()J

    .line 56
    .line 57
    .line 58
    move-result-wide v0

    .line 59
    iget-object p2, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mDb:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 60
    .line 61
    invoke-virtual {p2}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_0
    .catch Landroid/database/SQLException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 62
    .line 63
    .line 64
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mDb:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 65
    .line 66
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->endTransaction()V

    .line 67
    .line 68
    .line 69
    return-wide v0

    .line 70
    :goto_1
    :try_start_1
    const-string v0, "DatabaseUtils"

    .line 71
    .line 72
    new-instance v1, Ljava/lang/StringBuilder;

    .line 73
    .line 74
    invoke-direct {v1}, Ljava/lang/StringBuilder;-><init>()V

    .line 75
    .line 76
    .line 77
    const-string v2, "Error inserting "

    .line 78
    .line 79
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 80
    .line 81
    .line 82
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 83
    .line 84
    .line 85
    const-string p1, " into table  "

    .line 86
    .line 87
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 88
    .line 89
    .line 90
    iget-object p1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mTableName:Ljava/lang/String;

    .line 91
    .line 92
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 93
    .line 94
    .line 95
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object p1

    .line 99
    invoke-static {v0, p1, p2}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 100
    .line 101
    .line 102
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mDb:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 103
    .line 104
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->endTransaction()V

    .line 105
    .line 106
    .line 107
    const-wide/16 p0, -0x1

    .line 108
    .line 109
    return-wide p0

    .line 110
    :goto_2
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mDb:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 111
    .line 112
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->endTransaction()V

    .line 113
    .line 114
    .line 115
    throw p1
.end method


# virtual methods
.method public bind(ID)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    invoke-virtual {p0, p1, p2, p3}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bindDouble(ID)V

    return-void
.end method

.method public bind(IF)V
    .locals 2

    .line 2
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    float-to-double v0, p2

    invoke-virtual {p0, p1, v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bindDouble(ID)V

    return-void
.end method

.method public bind(II)V
    .locals 2

    .line 4
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    int-to-long v0, p2

    invoke-virtual {p0, p1, v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bindLong(IJ)V

    return-void
.end method

.method public bind(IJ)V
    .locals 0

    .line 3
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    invoke-virtual {p0, p1, p2, p3}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bindLong(IJ)V

    return-void
.end method

.method public bind(ILjava/lang/String;)V
    .locals 0

    if-nez p2, :cond_0

    .line 8
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bindNull(I)V

    return-void

    .line 9
    :cond_0
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    invoke-virtual {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bindString(ILjava/lang/String;)V

    return-void
.end method

.method public bind(IZ)V
    .locals 2

    .line 5
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    if-eqz p2, :cond_0

    const-wide/16 v0, 0x1

    goto :goto_0

    :cond_0
    const-wide/16 v0, 0x0

    :goto_0
    invoke-virtual {p0, p1, v0, v1}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bindLong(IJ)V

    return-void
.end method

.method public bind(I[B)V
    .locals 0

    if-nez p2, :cond_0

    .line 6
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bindNull(I)V

    return-void

    .line 7
    :cond_0
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    invoke-virtual {p0, p1, p2}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bindBlob(I[B)V

    return-void
.end method

.method public bindNull(I)V
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->bindNull(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public close()V
    .locals 2

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mInsertStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-eqz v0, :cond_0

    .line 5
    .line 6
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 7
    .line 8
    .line 9
    iput-object v1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mInsertStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 10
    .line 11
    :cond_0
    iget-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mReplaceStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 12
    .line 13
    if-eqz v0, :cond_1

    .line 14
    .line 15
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 16
    .line 17
    .line 18
    iput-object v1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mReplaceStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 19
    .line 20
    :cond_1
    iput-object v1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mInsertSQL:Ljava/lang/String;

    .line 21
    .line 22
    iput-object v1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mColumns:Ljava/util/HashMap;

    .line 23
    .line 24
    return-void
.end method

.method public execute()J
    .locals 5

    .line 1
    const-string v0, "Error executing InsertHelper with table "

    .line 2
    .line 3
    iget-object v1, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    :try_start_0
    invoke-virtual {v1}, Lnet/zetetic/database/sqlcipher/SQLiteStatement;->executeInsert()J

    .line 9
    .line 10
    .line 11
    move-result-wide v0
    :try_end_0
    .catch Landroid/database/SQLException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    iput-object v2, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 13
    .line 14
    return-wide v0

    .line 15
    :catchall_0
    move-exception v0

    .line 16
    goto :goto_0

    .line 17
    :catch_0
    move-exception v1

    .line 18
    :try_start_1
    const-string v3, "DatabaseUtils"

    .line 19
    .line 20
    new-instance v4, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    invoke-direct {v4, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iget-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mTableName:Ljava/lang/String;

    .line 26
    .line 27
    invoke-virtual {v4, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 28
    .line 29
    .line 30
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 31
    .line 32
    .line 33
    move-result-object v0

    .line 34
    invoke-static {v3, v0, v1}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 35
    .line 36
    .line 37
    iput-object v2, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 38
    .line 39
    const-wide/16 v0, -0x1

    .line 40
    .line 41
    return-wide v0

    .line 42
    :goto_0
    iput-object v2, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 43
    .line 44
    throw v0

    .line 45
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string v0, "you must prepare this inserter before calling execute"

    .line 48
    .line 49
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0
.end method

.method public getColumnIndex(Ljava/lang/String;)I
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->getStatement(Z)Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 3
    .line 4
    .line 5
    iget-object p0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mColumns:Ljava/util/HashMap;

    .line 6
    .line 7
    invoke-virtual {p0, p1}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Ljava/lang/Integer;

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 21
    .line 22
    const-string v0, "column \'"

    .line 23
    .line 24
    const-string v1, "\' is invalid"

    .line 25
    .line 26
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw p0
.end method

.method public insert(Landroid/content/ContentValues;)J
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, v0}, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->insertInternal(Landroid/content/ContentValues;Z)J

    .line 3
    .line 4
    .line 5
    move-result-wide p0

    .line 6
    return-wide p0
.end method

.method public prepareForInsert()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, v0}, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->getStatement(Z)Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    iput-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 7
    .line 8
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->clearBindings()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public prepareForReplace()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, v0}, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->getStatement(Z)Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 3
    .line 4
    .line 5
    move-result-object v0

    .line 6
    iput-object v0, p0, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->mPreparedStatement:Lnet/zetetic/database/sqlcipher/SQLiteStatement;

    .line 7
    .line 8
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteProgram;->clearBindings()V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public replace(Landroid/content/ContentValues;)J
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-direct {p0, p1, v0}, Lnet/zetetic/database/DatabaseUtils$InsertHelper;->insertInternal(Landroid/content/ContentValues;Z)J

    .line 3
    .line 4
    .line 5
    move-result-wide p0

    .line 6
    return-wide p0
.end method
