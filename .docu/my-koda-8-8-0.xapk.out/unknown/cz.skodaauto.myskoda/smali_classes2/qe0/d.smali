.class public final Lqe0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Lve0/u;

.field public final c:Ljava/security/SecureRandom;


# direct methods
.method public constructor <init>(Landroid/content/Context;Lve0/u;Ljava/security/SecureRandom;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lqe0/d;->a:Landroid/content/Context;

    .line 5
    .line 6
    iput-object p2, p0, Lqe0/d;->b:Lve0/u;

    .line 7
    .line 8
    iput-object p3, p0, Lqe0/d;->c:Ljava/security/SecureRandom;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Ljava/lang/String;Lhy0/d;[Loa/b;ZZLrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p6, Lqe0/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p6

    .line 6
    check-cast v0, Lqe0/a;

    .line 7
    .line 8
    iget v1, v0, Lqe0/a;->j:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lqe0/a;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lqe0/a;

    .line 21
    .line 22
    invoke-direct {v0, p0, p6}, Lqe0/a;-><init>(Lqe0/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p6, v0, Lqe0/a;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lqe0/a;->j:I

    .line 30
    .line 31
    iget-object v3, p0, Lqe0/d;->a:Landroid/content/Context;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v4, :cond_1

    .line 37
    .line 38
    iget-object p0, v0, Lqe0/a;->g:Lla/s;

    .line 39
    .line 40
    iget-object p1, v0, Lqe0/a;->f:Lla/s;

    .line 41
    .line 42
    iget-object p3, v0, Lqe0/a;->e:[Loa/b;

    .line 43
    .line 44
    iget-object p2, v0, Lqe0/a;->d:Ljava/lang/String;

    .line 45
    .line 46
    invoke-static {p6}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    move-object v5, p2

    .line 50
    move-object p2, p1

    .line 51
    move-object p1, v5

    .line 52
    goto :goto_1

    .line 53
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw p0

    .line 61
    :cond_2
    invoke-static {p6}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    if-eqz p5, :cond_3

    .line 65
    .line 66
    if-eqz p4, :cond_3

    .line 67
    .line 68
    const-string p5, "sqlcipher"

    .line 69
    .line 70
    invoke-static {p5}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V

    .line 71
    .line 72
    .line 73
    :cond_3
    invoke-static {p2}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    move-result-object p2

    .line 77
    invoke-static {v3, p2, p1}, Llp/ff;->c(Landroid/content/Context;Ljava/lang/Class;Ljava/lang/String;)Lla/s;

    .line 78
    .line 79
    .line 80
    move-result-object p2

    .line 81
    if-eqz p4, :cond_5

    .line 82
    .line 83
    iput-object p1, v0, Lqe0/a;->d:Ljava/lang/String;

    .line 84
    .line 85
    iput-object p3, v0, Lqe0/a;->e:[Loa/b;

    .line 86
    .line 87
    iput-object p2, v0, Lqe0/a;->f:Lla/s;

    .line 88
    .line 89
    iput-object p2, v0, Lqe0/a;->g:Lla/s;

    .line 90
    .line 91
    iput v4, v0, Lqe0/a;->j:I

    .line 92
    .line 93
    invoke-virtual {p0, v0}, Lqe0/d;->c(Lrx0/c;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object p6

    .line 97
    if-ne p6, v1, :cond_4

    .line 98
    .line 99
    return-object v1

    .line 100
    :cond_4
    move-object p0, p2

    .line 101
    :goto_1
    check-cast p6, Ljava/lang/String;

    .line 102
    .line 103
    sget-object p4, Lly0/a;->a:Ljava/nio/charset/Charset;

    .line 104
    .line 105
    invoke-virtual {p6, p4}, Ljava/lang/String;->getBytes(Ljava/nio/charset/Charset;)[B

    .line 106
    .line 107
    .line 108
    move-result-object p4

    .line 109
    const-string p5, "getBytes(...)"

    .line 110
    .line 111
    invoke-static {p4, p5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 112
    .line 113
    .line 114
    new-instance p5, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;

    .line 115
    .line 116
    invoke-direct {p5, p4}, Lnet/zetetic/database/sqlcipher/SupportOpenHelperFactory;-><init>([B)V

    .line 117
    .line 118
    .line 119
    iput-object p5, p0, Lla/s;->h:Landroidx/sqlite/db/a;

    .line 120
    .line 121
    :cond_5
    array-length p0, p3

    .line 122
    invoke-static {p3, p0}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 123
    .line 124
    .line 125
    move-result-object p0

    .line 126
    check-cast p0, [Loa/b;

    .line 127
    .line 128
    invoke-virtual {p2, p0}, Lla/s;->a([Loa/b;)V

    .line 129
    .line 130
    .line 131
    const/4 p0, 0x0

    .line 132
    iput-boolean p0, p2, Lla/s;->p:Z

    .line 133
    .line 134
    iput-boolean v4, p2, Lla/s;->q:Z

    .line 135
    .line 136
    iput-boolean v4, p2, Lla/s;->r:Z

    .line 137
    .line 138
    const-string p0, "databaseName"

    .line 139
    .line 140
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {p2}, Lla/s;->b()Lla/u;

    .line 144
    .line 145
    .line 146
    move-result-object p0

    .line 147
    :try_start_0
    invoke-virtual {p0}, Lla/u;->a()V

    .line 148
    .line 149
    .line 150
    invoke-virtual {p0}, Lla/u;->b()V

    .line 151
    .line 152
    .line 153
    invoke-virtual {p0}, Lla/u;->i()Landroidx/sqlite/db/SupportSQLiteOpenHelper;

    .line 154
    .line 155
    .line 156
    move-result-object p3

    .line 157
    invoke-interface {p3}, Landroidx/sqlite/db/SupportSQLiteOpenHelper;->getWritableDatabase()Landroidx/sqlite/db/SupportSQLiteDatabase;

    .line 158
    .line 159
    .line 160
    move-result-object p3

    .line 161
    new-instance p4, Lpy/a;

    .line 162
    .line 163
    const/16 p5, 0xf

    .line 164
    .line 165
    invoke-direct {p4, p5}, Lpy/a;-><init>(I)V

    .line 166
    .line 167
    .line 168
    invoke-interface {p3, p4}, Landroidx/sqlite/db/SupportSQLiteDatabase;->query(Landroidx/sqlite/db/SupportSQLiteQuery;)Landroid/database/Cursor;
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 169
    .line 170
    .line 171
    return-object p0

    .line 172
    :catch_0
    move-exception p3

    .line 173
    new-instance p4, Lqe0/e;

    .line 174
    .line 175
    const/4 p5, 0x0

    .line 176
    invoke-direct {p4, p3, p5}, Lqe0/e;-><init>(Landroid/database/sqlite/SQLiteException;I)V

    .line 177
    .line 178
    .line 179
    invoke-static {p2, p4}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {p3}, Ljava/lang/Throwable;->getMessage()Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object p4

    .line 186
    if-eqz p4, :cond_6

    .line 187
    .line 188
    const-string p5, "file is not a database"

    .line 189
    .line 190
    invoke-static {p4, p5, v4}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 191
    .line 192
    .line 193
    move-result p4

    .line 194
    if-ne p4, v4, :cond_6

    .line 195
    .line 196
    invoke-virtual {v3}, Landroid/content/Context;->databaseList()[Ljava/lang/String;

    .line 197
    .line 198
    .line 199
    move-result-object p4

    .line 200
    const-string p5, "databaseList(...)"

    .line 201
    .line 202
    invoke-static {p4, p5}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 203
    .line 204
    .line 205
    invoke-static {p1, p4}, Lmx0/n;->e(Ljava/lang/Object;[Ljava/lang/Object;)Z

    .line 206
    .line 207
    .line 208
    move-result p4

    .line 209
    if-eqz p4, :cond_6

    .line 210
    .line 211
    invoke-virtual {v3, p1}, Landroid/content/Context;->deleteDatabase(Ljava/lang/String;)Z

    .line 212
    .line 213
    .line 214
    new-instance p1, Lqe0/e;

    .line 215
    .line 216
    const/4 p4, 0x1

    .line 217
    invoke-direct {p1, p3, p4}, Lqe0/e;-><init>(Landroid/database/sqlite/SQLiteException;I)V

    .line 218
    .line 219
    .line 220
    invoke-static {p2, p1}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 221
    .line 222
    .line 223
    invoke-virtual {p2}, Lla/s;->b()Lla/u;

    .line 224
    .line 225
    .line 226
    :cond_6
    return-object p0
.end method

.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Lqe0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lqe0/b;

    .line 7
    .line 8
    iget v1, v0, Lqe0/b;->g:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lqe0/b;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lqe0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lqe0/b;-><init>(Lqe0/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lqe0/b;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lqe0/b;->g:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    iget-object p0, v0, Lqe0/b;->d:Ljava/lang/String;

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    return-object p0

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance p1, Ljava/lang/StringBuilder;

    .line 54
    .line 55
    invoke-direct {p1}, Ljava/lang/StringBuilder;-><init>()V

    .line 56
    .line 57
    .line 58
    const/16 v2, 0x62

    .line 59
    .line 60
    iget-object v4, p0, Lqe0/d;->c:Ljava/security/SecureRandom;

    .line 61
    .line 62
    invoke-virtual {v4, v2}, Ljava/util/Random;->nextInt(I)I

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    add-int/lit8 v2, v2, 0x1e

    .line 67
    .line 68
    const/4 v5, 0x0

    .line 69
    :goto_1
    if-ge v5, v2, :cond_3

    .line 70
    .line 71
    const/16 v6, 0x4c

    .line 72
    .line 73
    invoke-virtual {v4, v6}, Ljava/util/Random;->nextInt(I)I

    .line 74
    .line 75
    .line 76
    move-result v6

    .line 77
    const-string v7, "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz|!\u00a3$%&/=@#(){}"

    .line 78
    .line 79
    invoke-virtual {v7, v6}, Ljava/lang/String;->charAt(I)C

    .line 80
    .line 81
    .line 82
    move-result v6

    .line 83
    invoke-virtual {p1, v6}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    add-int/lit8 v5, v5, 0x1

    .line 87
    .line 88
    goto :goto_1

    .line 89
    :cond_3
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    iput-object p1, v0, Lqe0/b;->d:Ljava/lang/String;

    .line 94
    .line 95
    iput v3, v0, Lqe0/b;->g:I

    .line 96
    .line 97
    iget-object p0, p0, Lqe0/d;->b:Lve0/u;

    .line 98
    .line 99
    const-string v2, "database_phrase"

    .line 100
    .line 101
    invoke-virtual {p0, v2, p1, v0}, Lve0/u;->n(Ljava/lang/String;Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p0

    .line 105
    if-ne p0, v1, :cond_4

    .line 106
    .line 107
    return-object v1

    .line 108
    :cond_4
    return-object p1
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 5

    .line 1
    instance-of v0, p1, Lqe0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lqe0/c;

    .line 7
    .line 8
    iget v1, v0, Lqe0/c;->f:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lqe0/c;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lqe0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lqe0/c;-><init>(Lqe0/d;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lqe0/c;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lqe0/c;->f:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    return-object p1

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    iput v4, v0, Lqe0/c;->f:I

    .line 59
    .line 60
    iget-object p1, p0, Lqe0/d;->b:Lve0/u;

    .line 61
    .line 62
    const-string v2, "database_phrase"

    .line 63
    .line 64
    invoke-virtual {p1, v2, v0}, Lve0/u;->f(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    if-ne p1, v1, :cond_4

    .line 69
    .line 70
    goto :goto_2

    .line 71
    :cond_4
    :goto_1
    check-cast p1, Ljava/lang/String;

    .line 72
    .line 73
    if-nez p1, :cond_6

    .line 74
    .line 75
    iput v3, v0, Lqe0/c;->f:I

    .line 76
    .line 77
    invoke-virtual {p0, v0}, Lqe0/d;->b(Lrx0/c;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    if-ne p0, v1, :cond_5

    .line 82
    .line 83
    :goto_2
    return-object v1

    .line 84
    :cond_5
    return-object p0

    .line 85
    :cond_6
    return-object p1
.end method
