.class public final Lwa/f;
.super Landroid/database/sqlite/SQLiteOpenHelper;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic k:I


# instance fields
.field public final d:Landroid/content/Context;

.field public final e:Lpv/g;

.field public final f:Lb11/a;

.field public final g:Z

.field public h:Z

.field public final i:Lya/a;

.field public j:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/String;Lpv/g;Lb11/a;Z)V
    .locals 7

    .line 1
    const-string v0, "context"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "callback"

    .line 7
    .line 8
    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget v5, p4, Lb11/a;->e:I

    .line 12
    .line 13
    new-instance v6, Lwa/c;

    .line 14
    .line 15
    invoke-direct {v6, p4, p3}, Lwa/c;-><init>(Lb11/a;Lpv/g;)V

    .line 16
    .line 17
    .line 18
    const/4 v4, 0x0

    .line 19
    move-object v1, p0

    .line 20
    move-object v2, p1

    .line 21
    move-object v3, p2

    .line 22
    invoke-direct/range {v1 .. v6}, Landroid/database/sqlite/SQLiteOpenHelper;-><init>(Landroid/content/Context;Ljava/lang/String;Landroid/database/sqlite/SQLiteDatabase$CursorFactory;ILandroid/database/DatabaseErrorHandler;)V

    .line 23
    .line 24
    .line 25
    iput-object v2, v1, Lwa/f;->d:Landroid/content/Context;

    .line 26
    .line 27
    iput-object p3, v1, Lwa/f;->e:Lpv/g;

    .line 28
    .line 29
    iput-object p4, v1, Lwa/f;->f:Lb11/a;

    .line 30
    .line 31
    iput-boolean p5, v1, Lwa/f;->g:Z

    .line 32
    .line 33
    new-instance p0, Lya/a;

    .line 34
    .line 35
    if-nez v3, :cond_0

    .line 36
    .line 37
    invoke-static {}, Ljava/util/UUID;->randomUUID()Ljava/util/UUID;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    invoke-virtual {p1}, Ljava/util/UUID;->toString()Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p2

    .line 45
    const-string p1, "toString(...)"

    .line 46
    .line 47
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    goto :goto_0

    .line 51
    :cond_0
    move-object p2, v3

    .line 52
    :goto_0
    invoke-virtual {v2}, Landroid/content/Context;->getCacheDir()Ljava/io/File;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    const/4 p3, 0x0

    .line 57
    invoke-direct {p0, p2, p1, p3}, Lya/a;-><init>(Ljava/lang/String;Ljava/io/File;Z)V

    .line 58
    .line 59
    .line 60
    iput-object p0, v1, Lwa/f;->i:Lya/a;

    .line 61
    .line 62
    return-void
.end method


# virtual methods
.method public final a(Z)Landroidx/sqlite/db/SupportSQLiteDatabase;
    .locals 3

    .line 1
    iget-object v0, p0, Lwa/f;->i:Lya/a;

    .line 2
    .line 3
    :try_start_0
    iget-boolean v1, p0, Lwa/f;->j:Z

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    if-nez v1, :cond_0

    .line 7
    .line 8
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getDatabaseName()Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    const/4 v1, 0x1

    .line 15
    goto :goto_0

    .line 16
    :catchall_0
    move-exception p0

    .line 17
    goto :goto_1

    .line 18
    :cond_0
    move v1, v2

    .line 19
    :goto_0
    invoke-virtual {v0, v1}, Lya/a;->a(Z)V

    .line 20
    .line 21
    .line 22
    iput-boolean v2, p0, Lwa/f;->h:Z

    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lwa/f;->b(Z)Landroid/database/sqlite/SQLiteDatabase;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    iget-boolean v2, p0, Lwa/f;->h:Z

    .line 29
    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    invoke-virtual {p0}, Lwa/f;->close()V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lwa/f;->a(Z)Landroidx/sqlite/db/SupportSQLiteDatabase;

    .line 36
    .line 37
    .line 38
    move-result-object p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 39
    invoke-virtual {v0}, Lya/a;->b()V

    .line 40
    .line 41
    .line 42
    return-object p0

    .line 43
    :cond_1
    :try_start_1
    iget-object p0, p0, Lwa/f;->e:Lpv/g;

    .line 44
    .line 45
    invoke-static {p0, v1}, Llp/fd;->f(Lpv/g;Landroid/database/sqlite/SQLiteDatabase;)Lwa/b;

    .line 46
    .line 47
    .line 48
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 49
    invoke-virtual {v0}, Lya/a;->b()V

    .line 50
    .line 51
    .line 52
    return-object p0

    .line 53
    :goto_1
    invoke-virtual {v0}, Lya/a;->b()V

    .line 54
    .line 55
    .line 56
    throw p0
.end method

.method public final b(Z)Landroid/database/sqlite/SQLiteDatabase;
    .locals 5

    .line 1
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getDatabaseName()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    iget-boolean v1, p0, Lwa/f;->j:Z

    .line 6
    .line 7
    iget-object v2, p0, Lwa/f;->d:Landroid/content/Context;

    .line 8
    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    if-nez v1, :cond_0

    .line 12
    .line 13
    invoke-virtual {v2, v0}, Landroid/content/Context;->getDatabasePath(Ljava/lang/String;)Ljava/io/File;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-virtual {v1}, Ljava/io/File;->getParentFile()Ljava/io/File;

    .line 18
    .line 19
    .line 20
    move-result-object v1

    .line 21
    if-eqz v1, :cond_0

    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/io/File;->mkdirs()Z

    .line 24
    .line 25
    .line 26
    invoke-virtual {v1}, Ljava/io/File;->isDirectory()Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-nez v3, :cond_0

    .line 31
    .line 32
    new-instance v3, Ljava/lang/StringBuilder;

    .line 33
    .line 34
    const-string v4, "Invalid database parent file, not a directory: "

    .line 35
    .line 36
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 43
    .line 44
    .line 45
    move-result-object v1

    .line 46
    const-string v3, "SupportSQLite"

    .line 47
    .line 48
    invoke-static {v3, v1}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 49
    .line 50
    .line 51
    :cond_0
    if-eqz p1, :cond_1

    .line 52
    .line 53
    :try_start_0
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    return-object v1

    .line 61
    :cond_1
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getReadableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 66
    .line 67
    .line 68
    return-object v1

    .line 69
    :catchall_0
    const-wide/16 v3, 0x1f4

    .line 70
    .line 71
    :try_start_1
    invoke-static {v3, v4}, Ljava/lang/Thread;->sleep(J)V
    :try_end_1
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_0

    .line 72
    .line 73
    .line 74
    :catch_0
    if-eqz p1, :cond_2

    .line 75
    .line 76
    :try_start_2
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    .line 77
    .line 78
    .line 79
    move-result-object v1

    .line 80
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    goto :goto_0

    .line 84
    :catchall_1
    move-exception v1

    .line 85
    goto :goto_1

    .line 86
    :cond_2
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getReadableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    .line 87
    .line 88
    .line 89
    move-result-object v1

    .line 90
    invoke-static {v1}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 91
    .line 92
    .line 93
    :goto_0
    return-object v1

    .line 94
    :goto_1
    instance-of v3, v1, Lwa/d;

    .line 95
    .line 96
    if-eqz v3, :cond_6

    .line 97
    .line 98
    check-cast v1, Lwa/d;

    .line 99
    .line 100
    iget-object v3, v1, Lwa/d;->d:Lwa/e;

    .line 101
    .line 102
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 103
    .line 104
    .line 105
    move-result v3

    .line 106
    iget-object v1, v1, Lwa/d;->e:Ljava/lang/Throwable;

    .line 107
    .line 108
    if-eqz v3, :cond_5

    .line 109
    .line 110
    const/4 v4, 0x1

    .line 111
    if-eq v3, v4, :cond_5

    .line 112
    .line 113
    const/4 v4, 0x2

    .line 114
    if-eq v3, v4, :cond_5

    .line 115
    .line 116
    const/4 v4, 0x3

    .line 117
    if-eq v3, v4, :cond_5

    .line 118
    .line 119
    const/4 v4, 0x4

    .line 120
    if-ne v3, v4, :cond_4

    .line 121
    .line 122
    instance-of v3, v1, Landroid/database/sqlite/SQLiteException;

    .line 123
    .line 124
    if-eqz v3, :cond_3

    .line 125
    .line 126
    goto :goto_2

    .line 127
    :cond_3
    throw v1

    .line 128
    :cond_4
    new-instance p0, La8/r0;

    .line 129
    .line 130
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 131
    .line 132
    .line 133
    throw p0

    .line 134
    :cond_5
    throw v1

    .line 135
    :cond_6
    :goto_2
    instance-of v3, v1, Landroid/database/sqlite/SQLiteException;

    .line 136
    .line 137
    if-eqz v3, :cond_8

    .line 138
    .line 139
    if-eqz v0, :cond_8

    .line 140
    .line 141
    iget-boolean v3, p0, Lwa/f;->g:Z

    .line 142
    .line 143
    if-eqz v3, :cond_8

    .line 144
    .line 145
    invoke-virtual {v2, v0}, Landroid/content/Context;->deleteDatabase(Ljava/lang/String;)Z

    .line 146
    .line 147
    .line 148
    if-eqz p1, :cond_7

    .line 149
    .line 150
    :try_start_3
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getWritableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    .line 151
    .line 152
    .line 153
    move-result-object p0

    .line 154
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 155
    .line 156
    .line 157
    goto :goto_3

    .line 158
    :catch_1
    move-exception p0

    .line 159
    goto :goto_4

    .line 160
    :cond_7
    invoke-virtual {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->getReadableDatabase()Landroid/database/sqlite/SQLiteDatabase;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V
    :try_end_3
    .catch Lwa/d; {:try_start_3 .. :try_end_3} :catch_1

    .line 165
    .line 166
    .line 167
    :goto_3
    return-object p0

    .line 168
    :goto_4
    iget-object p0, p0, Lwa/d;->e:Ljava/lang/Throwable;

    .line 169
    .line 170
    throw p0

    .line 171
    :cond_8
    throw v1
.end method

.method public final close()V
    .locals 3

    .line 1
    iget-object v0, p0, Lwa/f;->i:Lya/a;

    .line 2
    .line 3
    :try_start_0
    iget-boolean v1, v0, Lya/a;->a:Z

    .line 4
    .line 5
    invoke-virtual {v0, v1}, Lya/a;->a(Z)V

    .line 6
    .line 7
    .line 8
    invoke-super {p0}, Landroid/database/sqlite/SQLiteOpenHelper;->close()V

    .line 9
    .line 10
    .line 11
    iget-object v1, p0, Lwa/f;->e:Lpv/g;

    .line 12
    .line 13
    const/4 v2, 0x0

    .line 14
    iput-object v2, v1, Lpv/g;->e:Ljava/lang/Object;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    iput-boolean v1, p0, Lwa/f;->j:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    .line 19
    invoke-virtual {v0}, Lya/a;->b()V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :catchall_0
    move-exception p0

    .line 24
    invoke-virtual {v0}, Lya/a;->b()V

    .line 25
    .line 26
    .line 27
    throw p0
.end method

.method public final onConfigure(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 3

    .line 1
    const-string v0, "db"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lwa/f;->h:Z

    .line 7
    .line 8
    iget-object v1, p0, Lwa/f;->f:Lb11/a;

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    iget v0, v1, Lb11/a;->e:I

    .line 13
    .line 14
    invoke-virtual {p1}, Landroid/database/sqlite/SQLiteDatabase;->getVersion()I

    .line 15
    .line 16
    .line 17
    move-result v2

    .line 18
    if-eq v0, v2, :cond_0

    .line 19
    .line 20
    const/4 v0, 0x1

    .line 21
    invoke-virtual {p1, v0}, Landroid/database/sqlite/SQLiteDatabase;->setMaxSqlCacheSize(I)V

    .line 22
    .line 23
    .line 24
    :cond_0
    :try_start_0
    iget-object p0, p0, Lwa/f;->e:Lpv/g;

    .line 25
    .line 26
    invoke-static {p0, p1}, Llp/fd;->f(Lpv/g;Landroid/database/sqlite/SQLiteDatabase;)Lwa/b;

    .line 27
    .line 28
    .line 29
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 30
    .line 31
    .line 32
    return-void

    .line 33
    :catchall_0
    move-exception p0

    .line 34
    new-instance p1, Lwa/d;

    .line 35
    .line 36
    sget-object v0, Lwa/e;->d:Lwa/e;

    .line 37
    .line 38
    invoke-direct {p1, v0, p0}, Lwa/d;-><init>(Lwa/e;Ljava/lang/Throwable;)V

    .line 39
    .line 40
    .line 41
    throw p1
.end method

.method public final onCreate(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 1

    .line 1
    const-string v0, "sqLiteDatabase"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    :try_start_0
    iget-object v0, p0, Lwa/f;->f:Lb11/a;

    .line 7
    .line 8
    iget-object p0, p0, Lwa/f;->e:Lpv/g;

    .line 9
    .line 10
    invoke-static {p0, p1}, Llp/fd;->f(Lpv/g;Landroid/database/sqlite/SQLiteDatabase;)Lwa/b;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    invoke-virtual {v0, p0}, Lb11/a;->e(Landroidx/sqlite/db/SupportSQLiteDatabase;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    .line 16
    .line 17
    return-void

    .line 18
    :catchall_0
    move-exception p0

    .line 19
    new-instance p1, Lwa/d;

    .line 20
    .line 21
    sget-object v0, Lwa/e;->e:Lwa/e;

    .line 22
    .line 23
    invoke-direct {p1, v0, p0}, Lwa/d;-><init>(Lwa/e;Ljava/lang/Throwable;)V

    .line 24
    .line 25
    .line 26
    throw p1
.end method

.method public final onDowngrade(Landroid/database/sqlite/SQLiteDatabase;II)V
    .locals 1

    .line 1
    const-string v0, "db"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    iput-boolean v0, p0, Lwa/f;->h:Z

    .line 8
    .line 9
    :try_start_0
    iget-object v0, p0, Lwa/f;->f:Lb11/a;

    .line 10
    .line 11
    iget-object p0, p0, Lwa/f;->e:Lpv/g;

    .line 12
    .line 13
    invoke-static {p0, p1}, Llp/fd;->f(Lpv/g;Landroid/database/sqlite/SQLiteDatabase;)Lwa/b;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {v0, p0, p2, p3}, Lb11/a;->f(Landroidx/sqlite/db/SupportSQLiteDatabase;II)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    new-instance p1, Lwa/d;

    .line 23
    .line 24
    sget-object p2, Lwa/e;->g:Lwa/e;

    .line 25
    .line 26
    invoke-direct {p1, p2, p0}, Lwa/d;-><init>(Lwa/e;Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    throw p1
.end method

.method public final onOpen(Landroid/database/sqlite/SQLiteDatabase;)V
    .locals 2

    .line 1
    const-string v0, "db"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-boolean v0, p0, Lwa/f;->h:Z

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    :try_start_0
    iget-object v0, p0, Lwa/f;->f:Lb11/a;

    .line 11
    .line 12
    iget-object v1, p0, Lwa/f;->e:Lpv/g;

    .line 13
    .line 14
    invoke-static {v1, p1}, Llp/fd;->f(Lpv/g;Landroid/database/sqlite/SQLiteDatabase;)Lwa/b;

    .line 15
    .line 16
    .line 17
    move-result-object p1

    .line 18
    invoke-virtual {v0, p1}, Lb11/a;->g(Landroidx/sqlite/db/SupportSQLiteDatabase;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 19
    .line 20
    .line 21
    goto :goto_0

    .line 22
    :catchall_0
    move-exception p0

    .line 23
    new-instance p1, Lwa/d;

    .line 24
    .line 25
    sget-object v0, Lwa/e;->h:Lwa/e;

    .line 26
    .line 27
    invoke-direct {p1, v0, p0}, Lwa/d;-><init>(Lwa/e;Ljava/lang/Throwable;)V

    .line 28
    .line 29
    .line 30
    throw p1

    .line 31
    :cond_0
    :goto_0
    const/4 p1, 0x1

    .line 32
    iput-boolean p1, p0, Lwa/f;->j:Z

    .line 33
    .line 34
    return-void
.end method

.method public final onUpgrade(Landroid/database/sqlite/SQLiteDatabase;II)V
    .locals 1

    .line 1
    const-string v0, "sqLiteDatabase"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    iput-boolean v0, p0, Lwa/f;->h:Z

    .line 8
    .line 9
    :try_start_0
    iget-object v0, p0, Lwa/f;->f:Lb11/a;

    .line 10
    .line 11
    iget-object p0, p0, Lwa/f;->e:Lpv/g;

    .line 12
    .line 13
    invoke-static {p0, p1}, Llp/fd;->f(Lpv/g;Landroid/database/sqlite/SQLiteDatabase;)Lwa/b;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    invoke-virtual {v0, p0, p2, p3}, Lb11/a;->h(Landroidx/sqlite/db/SupportSQLiteDatabase;II)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 18
    .line 19
    .line 20
    return-void

    .line 21
    :catchall_0
    move-exception p0

    .line 22
    new-instance p1, Lwa/d;

    .line 23
    .line 24
    sget-object p2, Lwa/e;->f:Lwa/e;

    .line 25
    .line 26
    invoke-direct {p1, p2, p0}, Lwa/d;-><init>(Lwa/e;Ljava/lang/Throwable;)V

    .line 27
    .line 28
    .line 29
    throw p1
.end method
