.class public abstract Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/sqlite/db/SupportSQLiteOpenHelper;


# static fields
.field private static final DEBUG_STRICT_READONLY:Z = false

.field private static final TAG:Ljava/lang/String; = "SQLiteOpenHelper"


# instance fields
.field private final mContext:Landroid/content/Context;

.field private mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

.field private final mDatabaseHook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

.field private mEnableWriteAheadLogging:Z

.field private final mErrorHandler:Lnet/zetetic/database/DatabaseErrorHandler;

.field private final mFactory:Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;

.field private mIsInitializing:Z

.field private final mMinimumSupportedVersion:I

.field private final mName:Ljava/lang/String;

.field private final mNewVersion:I

.field private mPassword:[B


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;IILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;Z)V
    .locals 0

    .line 4
    invoke-static {p3}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->getBytes(Ljava/lang/String;)[B

    move-result-object p3

    invoke-direct/range {p0 .. p9}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;-><init>(Landroid/content/Context;Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;IILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;Z)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;I)V
    .locals 6

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move v4, p4

    .line 1
    invoke-direct/range {v0 .. v5}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;-><init>(Landroid/content/Context;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;IILnet/zetetic/database/DatabaseErrorHandler;)V
    .locals 11

    const/4 v0, 0x0

    .line 3
    new-array v4, v0, [B

    const/4 v9, 0x0

    const/4 v10, 0x0

    move-object v1, p0

    move-object v2, p1

    move-object v3, p2

    move-object v5, p3

    move v6, p4

    move/from16 v7, p5

    move-object/from16 v8, p6

    invoke-direct/range {v1 .. v10}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;-><init>(Landroid/content/Context;Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;IILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;Z)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;)V
    .locals 7

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move-object v2, p2

    move-object v3, p3

    move v4, p4

    move-object v6, p5

    .line 2
    invoke-direct/range {v0 .. v6}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;-><init>(Landroid/content/Context;Ljava/lang/String;Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;IILnet/zetetic/database/DatabaseErrorHandler;)V

    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;IILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;Z)V
    .locals 1

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    if-lt p5, v0, :cond_0

    .line 6
    iput-object p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mContext:Landroid/content/Context;

    .line 7
    iput-object p2, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mName:Ljava/lang/String;

    .line 8
    iput-object p3, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mPassword:[B

    .line 9
    iput-object p4, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mFactory:Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;

    .line 10
    iput p5, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mNewVersion:I

    .line 11
    iput-object p7, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mErrorHandler:Lnet/zetetic/database/DatabaseErrorHandler;

    .line 12
    iput-object p8, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabaseHook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

    .line 13
    iput-boolean p9, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mEnableWriteAheadLogging:Z

    const/4 p1, 0x0

    .line 14
    invoke-static {p1, p6}, Ljava/lang/Math;->max(II)I

    move-result p1

    iput p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mMinimumSupportedVersion:I

    return-void

    .line 15
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Version must be >= 1, was "

    .line 16
    invoke-static {p5, p1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    move-result-object p1

    .line 17
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method private static getBytes(Ljava/lang/String;)[B
    .locals 1

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/String;->length()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-static {p0}, Ljava/nio/CharBuffer;->wrap(Ljava/lang/CharSequence;)Ljava/nio/CharBuffer;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    const-string v0, "UTF-8"

    .line 15
    .line 16
    invoke-static {v0}, Ljava/nio/charset/Charset;->forName(Ljava/lang/String;)Ljava/nio/charset/Charset;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    invoke-virtual {v0, p0}, Ljava/nio/charset/Charset;->encode(Ljava/nio/CharBuffer;)Ljava/nio/ByteBuffer;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    invoke-virtual {p0}, Ljava/nio/Buffer;->limit()I

    .line 25
    .line 26
    .line 27
    move-result v0

    .line 28
    new-array v0, v0, [B

    .line 29
    .line 30
    invoke-virtual {p0, v0}, Ljava/nio/ByteBuffer;->get([B)Ljava/nio/ByteBuffer;

    .line 31
    .line 32
    .line 33
    return-object v0

    .line 34
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 35
    new-array p0, p0, [B

    .line 36
    .line 37
    return-object p0
.end method

.method private getDatabaseLocked(Z)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 14

    .line 1
    const-string v1, "Opened "

    .line 2
    .line 3
    const-string v2, "Unable to delete obsolete database "

    .line 4
    .line 5
    const-string v3, "Can\'t upgrade read-only database from version "

    .line 6
    .line 7
    const-string v4, "Couldn\'t open "

    .line 8
    .line 9
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 10
    .line 11
    const/4 v5, 0x0

    .line 12
    if-eqz v0, :cond_2

    .line 13
    .line 14
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isOpen()Z

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    if-nez v0, :cond_0

    .line 19
    .line 20
    iput-object v5, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :cond_0
    if-eqz p1, :cond_1

    .line 24
    .line 25
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 26
    .line 27
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isReadOnly()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-nez v0, :cond_2

    .line 32
    .line 33
    :cond_1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 34
    .line 35
    return-object p0

    .line 36
    :cond_2
    :goto_0
    iget-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mIsInitializing:Z

    .line 37
    .line 38
    if-nez v0, :cond_13

    .line 39
    .line 40
    iget-object v6, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 41
    .line 42
    const/4 v0, 0x1

    .line 43
    const/4 v7, 0x0

    .line 44
    :try_start_0
    iput-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mIsInitializing:Z

    .line 45
    .line 46
    if-eqz v6, :cond_3

    .line 47
    .line 48
    if-eqz p1, :cond_8

    .line 49
    .line 50
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isReadOnly()Z

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    if-eqz v0, :cond_8

    .line 55
    .line 56
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->reopenReadWrite()V

    .line 57
    .line 58
    .line 59
    goto/16 :goto_5

    .line 60
    .line 61
    :catchall_0
    move-exception v0

    .line 62
    move-object p1, v0

    .line 63
    goto/16 :goto_9

    .line 64
    .line 65
    :cond_3
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mName:Ljava/lang/String;

    .line 66
    .line 67
    if-nez v0, :cond_4

    .line 68
    .line 69
    invoke-static {v5}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->create(Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 70
    .line 71
    .line 72
    move-result-object v6
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 73
    goto/16 :goto_5

    .line 74
    .line 75
    :cond_4
    :try_start_1
    const-string v5, "file:"

    .line 76
    .line 77
    invoke-virtual {v0, v5}, Ljava/lang/String;->startsWith(Ljava/lang/String;)Z

    .line 78
    .line 79
    .line 80
    move-result v5

    .line 81
    if-nez v5, :cond_5

    .line 82
    .line 83
    iget-object v5, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mContext:Landroid/content/Context;

    .line 84
    .line 85
    invoke-virtual {v5, v0}, Landroid/content/Context;->getDatabasePath(Ljava/lang/String;)Ljava/io/File;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    invoke-virtual {v0}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object v0

    .line 93
    :cond_5
    move-object v8, v0

    .line 94
    goto :goto_1

    .line 95
    :catch_0
    move-exception v0

    .line 96
    goto :goto_4

    .line 97
    :goto_1
    new-instance v0, Ljava/io/File;

    .line 98
    .line 99
    invoke-direct {v0, v8}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    new-instance v5, Ljava/io/File;

    .line 103
    .line 104
    invoke-virtual {v0}, Ljava/io/File;->getParent()Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v0

    .line 108
    invoke-direct {v5, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v5}, Ljava/io/File;->exists()Z

    .line 112
    .line 113
    .line 114
    move-result v0

    .line 115
    if-nez v0, :cond_6

    .line 116
    .line 117
    invoke-virtual {v5}, Ljava/io/File;->mkdirs()Z

    .line 118
    .line 119
    .line 120
    :cond_6
    iget-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mEnableWriteAheadLogging:Z

    .line 121
    .line 122
    if-eqz v0, :cond_7

    .line 123
    .line 124
    const/high16 v0, 0x30000000

    .line 125
    .line 126
    :goto_2
    move v11, v0

    .line 127
    goto :goto_3

    .line 128
    :cond_7
    const/high16 v0, 0x10000000

    .line 129
    .line 130
    goto :goto_2

    .line 131
    :goto_3
    iget-object v9, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mPassword:[B

    .line 132
    .line 133
    iget-object v10, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mFactory:Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;

    .line 134
    .line 135
    iget-object v12, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mErrorHandler:Lnet/zetetic/database/DatabaseErrorHandler;

    .line 136
    .line 137
    iget-object v13, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabaseHook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

    .line 138
    .line 139
    invoke-static/range {v8 .. v13}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 140
    .line 141
    .line 142
    move-result-object v6
    :try_end_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 143
    goto :goto_5

    .line 144
    :goto_4
    if-nez p1, :cond_11

    .line 145
    .line 146
    :try_start_2
    sget-object v5, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->TAG:Ljava/lang/String;

    .line 147
    .line 148
    new-instance v8, Ljava/lang/StringBuilder;

    .line 149
    .line 150
    invoke-direct {v8, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    iget-object v4, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mName:Ljava/lang/String;

    .line 154
    .line 155
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 156
    .line 157
    .line 158
    const-string v4, " for writing (will try read-only):"

    .line 159
    .line 160
    invoke-virtual {v8, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 161
    .line 162
    .line 163
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 164
    .line 165
    .line 166
    move-result-object v4

    .line 167
    invoke-static {v5, v4, v0}, Lnet/zetetic/database/Logger;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 168
    .line 169
    .line 170
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mContext:Landroid/content/Context;

    .line 171
    .line 172
    iget-object v4, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mName:Ljava/lang/String;

    .line 173
    .line 174
    invoke-virtual {v0, v4}, Landroid/content/Context;->getDatabasePath(Ljava/lang/String;)Ljava/io/File;

    .line 175
    .line 176
    .line 177
    move-result-object v0

    .line 178
    invoke-virtual {v0}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v8

    .line 182
    iget-object v9, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mPassword:[B

    .line 183
    .line 184
    iget-object v10, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mFactory:Lnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;

    .line 185
    .line 186
    iget-object v12, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mErrorHandler:Lnet/zetetic/database/DatabaseErrorHandler;

    .line 187
    .line 188
    iget-object v13, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabaseHook:Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;

    .line 189
    .line 190
    const/4 v11, 0x1

    .line 191
    invoke-static/range {v8 .. v13}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->openDatabase(Ljava/lang/String;[BLnet/zetetic/database/sqlcipher/SQLiteDatabase$CursorFactory;ILnet/zetetic/database/DatabaseErrorHandler;Lnet/zetetic/database/sqlcipher/SQLiteDatabaseHook;)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 192
    .line 193
    .line 194
    move-result-object v6

    .line 195
    :cond_8
    :goto_5
    invoke-virtual {p0, v6}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->onConfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;)V

    .line 196
    .line 197
    .line 198
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getVersion()I

    .line 199
    .line 200
    .line 201
    move-result v0

    .line 202
    iget v4, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mNewVersion:I

    .line 203
    .line 204
    if-eq v0, v4, :cond_f

    .line 205
    .line 206
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isReadOnly()Z

    .line 207
    .line 208
    .line 209
    move-result v4

    .line 210
    if-nez v4, :cond_e

    .line 211
    .line 212
    if-lez v0, :cond_b

    .line 213
    .line 214
    iget v3, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mMinimumSupportedVersion:I

    .line 215
    .line 216
    if-ge v0, v3, :cond_b

    .line 217
    .line 218
    new-instance v1, Ljava/io/File;

    .line 219
    .line 220
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getPath()Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v3

    .line 224
    invoke-direct {v1, v3}, Ljava/io/File;-><init>(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    invoke-virtual {p0, v6}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->onBeforeDelete(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;)V

    .line 228
    .line 229
    .line 230
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 231
    .line 232
    .line 233
    invoke-static {v1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->deleteDatabase(Ljava/io/File;)Z

    .line 234
    .line 235
    .line 236
    move-result v1

    .line 237
    if-eqz v1, :cond_a

    .line 238
    .line 239
    iput-boolean v7, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mIsInitializing:Z

    .line 240
    .line 241
    invoke-direct {p0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->getDatabaseLocked(Z)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 242
    .line 243
    .line 244
    move-result-object p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 245
    iput-boolean v7, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mIsInitializing:Z

    .line 246
    .line 247
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 248
    .line 249
    if-eq v6, p0, :cond_9

    .line 250
    .line 251
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 252
    .line 253
    .line 254
    :cond_9
    return-object p1

    .line 255
    :cond_a
    :try_start_3
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 256
    .line 257
    new-instance v1, Ljava/lang/StringBuilder;

    .line 258
    .line 259
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 260
    .line 261
    .line 262
    iget-object v2, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mName:Ljava/lang/String;

    .line 263
    .line 264
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 265
    .line 266
    .line 267
    const-string v2, " with version "

    .line 268
    .line 269
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 270
    .line 271
    .line 272
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 273
    .line 274
    .line 275
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 276
    .line 277
    .line 278
    move-result-object v0

    .line 279
    invoke-direct {p1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 280
    .line 281
    .line 282
    throw p1

    .line 283
    :cond_b
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->beginTransaction()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 284
    .line 285
    .line 286
    if-nez v0, :cond_c

    .line 287
    .line 288
    :try_start_4
    invoke-virtual {p0, v6}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->onCreate(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;)V

    .line 289
    .line 290
    .line 291
    goto :goto_6

    .line 292
    :catchall_1
    move-exception v0

    .line 293
    move-object p1, v0

    .line 294
    goto :goto_7

    .line 295
    :cond_c
    iget p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mNewVersion:I

    .line 296
    .line 297
    if-le v0, p1, :cond_d

    .line 298
    .line 299
    invoke-virtual {p0, v6, v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->onDowngrade(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;II)V

    .line 300
    .line 301
    .line 302
    goto :goto_6

    .line 303
    :cond_d
    invoke-virtual {p0, v6, v0, p1}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->onUpgrade(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;II)V

    .line 304
    .line 305
    .line 306
    :goto_6
    iget p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mNewVersion:I

    .line 307
    .line 308
    invoke-virtual {v6, p1}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->setVersion(I)V

    .line 309
    .line 310
    .line 311
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->setTransactionSuccessful()V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_1

    .line 312
    .line 313
    .line 314
    :try_start_5
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->endTransaction()V

    .line 315
    .line 316
    .line 317
    goto :goto_8

    .line 318
    :goto_7
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->endTransaction()V

    .line 319
    .line 320
    .line 321
    throw p1

    .line 322
    :cond_e
    new-instance p1, Landroid/database/sqlite/SQLiteException;

    .line 323
    .line 324
    new-instance v0, Ljava/lang/StringBuilder;

    .line 325
    .line 326
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->getVersion()I

    .line 330
    .line 331
    .line 332
    move-result v1

    .line 333
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 334
    .line 335
    .line 336
    const-string v1, " to "

    .line 337
    .line 338
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 339
    .line 340
    .line 341
    iget v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mNewVersion:I

    .line 342
    .line 343
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 344
    .line 345
    .line 346
    const-string v1, ": "

    .line 347
    .line 348
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 349
    .line 350
    .line 351
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mName:Ljava/lang/String;

    .line 352
    .line 353
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 354
    .line 355
    .line 356
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 357
    .line 358
    .line 359
    move-result-object v0

    .line 360
    invoke-direct {p1, v0}, Landroid/database/sqlite/SQLiteException;-><init>(Ljava/lang/String;)V

    .line 361
    .line 362
    .line 363
    throw p1

    .line 364
    :cond_f
    :goto_8
    invoke-virtual {p0, v6}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->onOpen(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;)V

    .line 365
    .line 366
    .line 367
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isReadOnly()Z

    .line 368
    .line 369
    .line 370
    move-result p1

    .line 371
    if-eqz p1, :cond_10

    .line 372
    .line 373
    sget-object p1, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->TAG:Ljava/lang/String;

    .line 374
    .line 375
    new-instance v0, Ljava/lang/StringBuilder;

    .line 376
    .line 377
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 378
    .line 379
    .line 380
    iget-object v1, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mName:Ljava/lang/String;

    .line 381
    .line 382
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 383
    .line 384
    .line 385
    const-string v1, " in read-only mode"

    .line 386
    .line 387
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 388
    .line 389
    .line 390
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 391
    .line 392
    .line 393
    move-result-object v0

    .line 394
    invoke-static {p1, v0}, Lnet/zetetic/database/Logger;->w(Ljava/lang/String;Ljava/lang/String;)V

    .line 395
    .line 396
    .line 397
    :cond_10
    iput-object v6, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_0

    .line 398
    .line 399
    iput-boolean v7, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mIsInitializing:Z

    .line 400
    .line 401
    return-object v6

    .line 402
    :cond_11
    :try_start_6
    throw v0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_0

    .line 403
    :goto_9
    iput-boolean v7, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mIsInitializing:Z

    .line 404
    .line 405
    if-eqz v6, :cond_12

    .line 406
    .line 407
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 408
    .line 409
    if-eq v6, p0, :cond_12

    .line 410
    .line 411
    invoke-virtual {v6}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 412
    .line 413
    .line 414
    :cond_12
    throw p1

    .line 415
    :cond_13
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 416
    .line 417
    const-string p1, "getDatabase called recursively"

    .line 418
    .line 419
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 420
    .line 421
    .line 422
    throw p0
.end method


# virtual methods
.method public declared-synchronized close()V
    .locals 2

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mIsInitializing:Z

    .line 3
    .line 4
    if-nez v0, :cond_1

    .line 5
    .line 6
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isOpen()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_0

    .line 15
    .line 16
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 17
    .line 18
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteClosable;->close()V

    .line 19
    .line 20
    .line 21
    const/4 v0, 0x0

    .line 22
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :catchall_0
    move-exception v0

    .line 26
    goto :goto_1

    .line 27
    :cond_0
    :goto_0
    monitor-exit p0

    .line 28
    return-void

    .line 29
    :cond_1
    :try_start_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 30
    .line 31
    const-string v1, "Closed during initialization"

    .line 32
    .line 33
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw v0

    .line 37
    :goto_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 38
    throw v0
.end method

.method public getDatabaseName()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mName:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public bridge synthetic getReadableDatabase()Landroidx/sqlite/db/SupportSQLiteDatabase;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->getReadableDatabase()Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public getReadableDatabase()Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 1

    .line 2
    monitor-enter p0

    const/4 v0, 0x0

    .line 3
    :try_start_0
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->getDatabaseLocked(Z)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object v0

    monitor-exit p0

    return-object v0

    :catchall_0
    move-exception v0

    .line 4
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public bridge synthetic getWritableDatabase()Landroidx/sqlite/db/SupportSQLiteDatabase;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->getWritableDatabase()Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object p0

    return-object p0
.end method

.method public getWritableDatabase()Lnet/zetetic/database/sqlcipher/SQLiteDatabase;
    .locals 1

    .line 2
    monitor-enter p0

    const/4 v0, 0x1

    .line 3
    :try_start_0
    invoke-direct {p0, v0}, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->getDatabaseLocked(Z)Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    move-result-object v0

    monitor-exit p0

    return-object v0

    :catchall_0
    move-exception v0

    .line 4
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    throw v0
.end method

.method public onBeforeDelete(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;)V
    .locals 0

    .line 1
    return-void
.end method

.method public onConfigure(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;)V
    .locals 0

    .line 1
    return-void
.end method

.method public abstract onCreate(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;)V
.end method

.method public onDowngrade(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;II)V
    .locals 1

    .line 1
    new-instance p0, Landroid/database/sqlite/SQLiteException;

    .line 2
    .line 3
    const-string p1, "Can\'t downgrade database from version "

    .line 4
    .line 5
    const-string v0, " to "

    .line 6
    .line 7
    invoke-static {p1, v0, p2, p3}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-direct {p0, p1}, Landroid/database/sqlite/SQLiteException;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    throw p0
.end method

.method public onOpen(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;)V
    .locals 0

    .line 1
    return-void
.end method

.method public abstract onUpgrade(Lnet/zetetic/database/sqlcipher/SQLiteDatabase;II)V
.end method

.method public setWriteAheadLoggingEnabled(Z)V
    .locals 1

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mEnableWriteAheadLogging:Z

    .line 3
    .line 4
    if-eq v0, p1, :cond_2

    .line 5
    .line 6
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 7
    .line 8
    if-eqz v0, :cond_1

    .line 9
    .line 10
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isOpen()Z

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    if-eqz v0, :cond_1

    .line 15
    .line 16
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 17
    .line 18
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->isReadOnly()Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-nez v0, :cond_1

    .line 23
    .line 24
    if-eqz p1, :cond_0

    .line 25
    .line 26
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 27
    .line 28
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->enableWriteAheadLogging()Z

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    :catchall_0
    move-exception p1

    .line 33
    goto :goto_1

    .line 34
    :cond_0
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mDatabase:Lnet/zetetic/database/sqlcipher/SQLiteDatabase;

    .line 35
    .line 36
    invoke-virtual {v0}, Lnet/zetetic/database/sqlcipher/SQLiteDatabase;->disableWriteAheadLogging()V

    .line 37
    .line 38
    .line 39
    :cond_1
    :goto_0
    iput-boolean p1, p0, Lnet/zetetic/database/sqlcipher/SQLiteOpenHelper;->mEnableWriteAheadLogging:Z

    .line 40
    .line 41
    :cond_2
    monitor-exit p0

    .line 42
    return-void

    .line 43
    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 44
    throw p1
.end method
