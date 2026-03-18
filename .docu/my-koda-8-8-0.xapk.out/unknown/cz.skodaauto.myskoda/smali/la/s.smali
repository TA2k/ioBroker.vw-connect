.class public final Lla/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lhy0/d;

.field public final b:Landroid/content/Context;

.field public final c:Ljava/lang/String;

.field public final d:Ljava/util/ArrayList;

.field public final e:Ljava/util/ArrayList;

.field public f:Ljava/util/concurrent/Executor;

.field public g:Ljava/util/concurrent/Executor;

.field public h:Landroidx/sqlite/db/a;

.field public i:Z

.field public final j:Lla/t;

.field public final k:J

.field public final l:Lfb/k;

.field public final m:Ljava/util/LinkedHashSet;

.field public final n:Ljava/util/LinkedHashSet;

.field public final o:Ljava/util/ArrayList;

.field public p:Z

.field public q:Z

.field public r:Z

.field public final s:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Ljava/lang/Class;Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Ljava/util/ArrayList;

    .line 5
    .line 6
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lla/s;->d:Ljava/util/ArrayList;

    .line 10
    .line 11
    new-instance v0, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 14
    .line 15
    .line 16
    iput-object v0, p0, Lla/s;->e:Ljava/util/ArrayList;

    .line 17
    .line 18
    sget-object v0, Lla/t;->d:Lla/t;

    .line 19
    .line 20
    iput-object v0, p0, Lla/s;->j:Lla/t;

    .line 21
    .line 22
    const-wide/16 v0, -0x1

    .line 23
    .line 24
    iput-wide v0, p0, Lla/s;->k:J

    .line 25
    .line 26
    new-instance v0, Lfb/k;

    .line 27
    .line 28
    const/4 v1, 0x2

    .line 29
    invoke-direct {v0, v1}, Lfb/k;-><init>(I)V

    .line 30
    .line 31
    .line 32
    iput-object v0, p0, Lla/s;->l:Lfb/k;

    .line 33
    .line 34
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 35
    .line 36
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 37
    .line 38
    .line 39
    iput-object v0, p0, Lla/s;->m:Ljava/util/LinkedHashSet;

    .line 40
    .line 41
    new-instance v0, Ljava/util/LinkedHashSet;

    .line 42
    .line 43
    invoke-direct {v0}, Ljava/util/LinkedHashSet;-><init>()V

    .line 44
    .line 45
    .line 46
    iput-object v0, p0, Lla/s;->n:Ljava/util/LinkedHashSet;

    .line 47
    .line 48
    new-instance v0, Ljava/util/ArrayList;

    .line 49
    .line 50
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 51
    .line 52
    .line 53
    iput-object v0, p0, Lla/s;->o:Ljava/util/ArrayList;

    .line 54
    .line 55
    const/4 v0, 0x1

    .line 56
    iput-boolean v0, p0, Lla/s;->p:Z

    .line 57
    .line 58
    iput-boolean v0, p0, Lla/s;->s:Z

    .line 59
    .line 60
    invoke-static {p2}, Ljp/p1;->f(Ljava/lang/Class;)Lhy0/d;

    .line 61
    .line 62
    .line 63
    move-result-object p2

    .line 64
    iput-object p2, p0, Lla/s;->a:Lhy0/d;

    .line 65
    .line 66
    iput-object p1, p0, Lla/s;->b:Landroid/content/Context;

    .line 67
    .line 68
    iput-object p3, p0, Lla/s;->c:Ljava/lang/String;

    .line 69
    .line 70
    return-void
.end method


# virtual methods
.method public final varargs a([Loa/b;)V
    .locals 7

    .line 1
    const-string v0, "migrations"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    array-length v1, p1

    .line 7
    const/4 v2, 0x0

    .line 8
    move v3, v2

    .line 9
    :goto_0
    if-ge v3, v1, :cond_0

    .line 10
    .line 11
    aget-object v4, p1, v3

    .line 12
    .line 13
    iget v5, v4, Loa/b;->a:I

    .line 14
    .line 15
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 16
    .line 17
    .line 18
    move-result-object v5

    .line 19
    iget-object v6, p0, Lla/s;->n:Ljava/util/LinkedHashSet;

    .line 20
    .line 21
    invoke-interface {v6, v5}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 22
    .line 23
    .line 24
    iget v4, v4, Loa/b;->b:I

    .line 25
    .line 26
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 27
    .line 28
    .line 29
    move-result-object v4

    .line 30
    invoke-interface {v6, v4}, Ljava/util/Set;->add(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    add-int/lit8 v3, v3, 0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    array-length v1, p1

    .line 37
    invoke-static {p1, v1}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p1

    .line 41
    check-cast p1, [Loa/b;

    .line 42
    .line 43
    iget-object p0, p0, Lla/s;->l:Lfb/k;

    .line 44
    .line 45
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 46
    .line 47
    .line 48
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    array-length v0, p1

    .line 52
    :goto_1
    if-ge v2, v0, :cond_1

    .line 53
    .line 54
    aget-object v1, p1, v2

    .line 55
    .line 56
    invoke-virtual {p0, v1}, Lfb/k;->c(Loa/b;)V

    .line 57
    .line 58
    .line 59
    add-int/lit8 v2, v2, 0x1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    return-void
.end method

.method public final b()Lla/u;
    .locals 25

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lla/s;->f:Ljava/util/concurrent/Executor;

    .line 4
    .line 5
    if-nez v1, :cond_0

    .line 6
    .line 7
    iget-object v2, v0, Lla/s;->g:Ljava/util/concurrent/Executor;

    .line 8
    .line 9
    if-nez v2, :cond_0

    .line 10
    .line 11
    sget-object v1, Ln/a;->c:Lha/c;

    .line 12
    .line 13
    iput-object v1, v0, Lla/s;->g:Ljava/util/concurrent/Executor;

    .line 14
    .line 15
    iput-object v1, v0, Lla/s;->f:Ljava/util/concurrent/Executor;

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    if-eqz v1, :cond_1

    .line 19
    .line 20
    iget-object v2, v0, Lla/s;->g:Ljava/util/concurrent/Executor;

    .line 21
    .line 22
    if-nez v2, :cond_1

    .line 23
    .line 24
    iput-object v1, v0, Lla/s;->g:Ljava/util/concurrent/Executor;

    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_1
    if-nez v1, :cond_2

    .line 28
    .line 29
    iget-object v1, v0, Lla/s;->g:Ljava/util/concurrent/Executor;

    .line 30
    .line 31
    iput-object v1, v0, Lla/s;->f:Ljava/util/concurrent/Executor;

    .line 32
    .line 33
    :cond_2
    :goto_0
    const-string v1, "migrationStartAndEndVersions"

    .line 34
    .line 35
    iget-object v2, v0, Lla/s;->n:Ljava/util/LinkedHashSet;

    .line 36
    .line 37
    invoke-static {v2, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    const-string v1, "migrationsNotRequiredFrom"

    .line 41
    .line 42
    iget-object v3, v0, Lla/s;->m:Ljava/util/LinkedHashSet;

    .line 43
    .line 44
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    invoke-interface {v2}, Ljava/util/Collection;->isEmpty()Z

    .line 48
    .line 49
    .line 50
    move-result v1

    .line 51
    if-nez v1, :cond_4

    .line 52
    .line 53
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 54
    .line 55
    .line 56
    move-result-object v1

    .line 57
    :goto_1
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 58
    .line 59
    .line 60
    move-result v2

    .line 61
    if-eqz v2, :cond_4

    .line 62
    .line 63
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object v2

    .line 67
    check-cast v2, Ljava/lang/Number;

    .line 68
    .line 69
    invoke-virtual {v2}, Ljava/lang/Number;->intValue()I

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 74
    .line 75
    .line 76
    move-result-object v4

    .line 77
    invoke-interface {v3, v4}, Ljava/util/Set;->contains(Ljava/lang/Object;)Z

    .line 78
    .line 79
    .line 80
    move-result v4

    .line 81
    if-nez v4, :cond_3

    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_3
    const-string v0, "Inconsistency detected. A Migration was supplied to addMigration() that has a start or end version equal to a start version supplied to fallbackToDestructiveMigrationFrom(). Start version is: "

    .line 85
    .line 86
    invoke-static {v2, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 87
    .line 88
    .line 89
    move-result-object v0

    .line 90
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 91
    .line 92
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 93
    .line 94
    .line 95
    move-result-object v0

    .line 96
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 97
    .line 98
    .line 99
    throw v1

    .line 100
    :cond_4
    iget-object v1, v0, Lla/s;->h:Landroidx/sqlite/db/a;

    .line 101
    .line 102
    if-nez v1, :cond_5

    .line 103
    .line 104
    new-instance v1, Lwa/h;

    .line 105
    .line 106
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 107
    .line 108
    .line 109
    :cond_5
    move-object v6, v1

    .line 110
    iget-wide v1, v0, Lla/s;->k:J

    .line 111
    .line 112
    const-wide/16 v4, 0x0

    .line 113
    .line 114
    cmp-long v1, v1, v4

    .line 115
    .line 116
    const/4 v4, 0x1

    .line 117
    if-lez v1, :cond_6

    .line 118
    .line 119
    move v1, v4

    .line 120
    goto :goto_2

    .line 121
    :cond_6
    const/4 v1, 0x0

    .line 122
    :goto_2
    const-string v5, "Required value was null."

    .line 123
    .line 124
    if-eqz v1, :cond_8

    .line 125
    .line 126
    iget-object v0, v0, Lla/s;->c:Ljava/lang/String;

    .line 127
    .line 128
    if-eqz v0, :cond_7

    .line 129
    .line 130
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 131
    .line 132
    invoke-direct {v0, v5}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    throw v0

    .line 136
    :cond_7
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 137
    .line 138
    const-string v1, "Cannot create auto-closing database for an in-memory database."

    .line 139
    .line 140
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    throw v0

    .line 144
    :cond_8
    move-object/from16 v16, v3

    .line 145
    .line 146
    new-instance v3, Lla/b;

    .line 147
    .line 148
    iget-boolean v9, v0, Lla/s;->i:Z

    .line 149
    .line 150
    iget-object v1, v0, Lla/s;->j:Lla/t;

    .line 151
    .line 152
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 153
    .line 154
    .line 155
    const-string v7, "context"

    .line 156
    .line 157
    move v8, v4

    .line 158
    iget-object v4, v0, Lla/s;->b:Landroid/content/Context;

    .line 159
    .line 160
    invoke-static {v4, v7}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 161
    .line 162
    .line 163
    sget-object v7, Lla/t;->d:Lla/t;

    .line 164
    .line 165
    if-eq v1, v7, :cond_9

    .line 166
    .line 167
    goto :goto_4

    .line 168
    :cond_9
    const-string v1, "activity"

    .line 169
    .line 170
    invoke-virtual {v4, v1}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v1

    .line 174
    instance-of v7, v1, Landroid/app/ActivityManager;

    .line 175
    .line 176
    if-eqz v7, :cond_a

    .line 177
    .line 178
    check-cast v1, Landroid/app/ActivityManager;

    .line 179
    .line 180
    goto :goto_3

    .line 181
    :cond_a
    const/4 v1, 0x0

    .line 182
    :goto_3
    if-eqz v1, :cond_b

    .line 183
    .line 184
    invoke-virtual {v1}, Landroid/app/ActivityManager;->isLowRamDevice()Z

    .line 185
    .line 186
    .line 187
    move-result v1

    .line 188
    if-nez v1, :cond_b

    .line 189
    .line 190
    sget-object v1, Lla/t;->f:Lla/t;

    .line 191
    .line 192
    goto :goto_4

    .line 193
    :cond_b
    sget-object v1, Lla/t;->e:Lla/t;

    .line 194
    .line 195
    :goto_4
    iget-object v11, v0, Lla/s;->f:Ljava/util/concurrent/Executor;

    .line 196
    .line 197
    if-eqz v11, :cond_31

    .line 198
    .line 199
    iget-object v12, v0, Lla/s;->g:Ljava/util/concurrent/Executor;

    .line 200
    .line 201
    if-eqz v12, :cond_30

    .line 202
    .line 203
    iget-boolean v14, v0, Lla/s;->p:Z

    .line 204
    .line 205
    iget-boolean v15, v0, Lla/s;->q:Z

    .line 206
    .line 207
    iget-boolean v5, v0, Lla/s;->r:Z

    .line 208
    .line 209
    const/16 v23, 0x0

    .line 210
    .line 211
    const/16 v24, 0x0

    .line 212
    .line 213
    move/from16 v22, v5

    .line 214
    .line 215
    iget-object v5, v0, Lla/s;->c:Ljava/lang/String;

    .line 216
    .line 217
    iget-object v7, v0, Lla/s;->l:Lfb/k;

    .line 218
    .line 219
    move v13, v8

    .line 220
    iget-object v8, v0, Lla/s;->d:Ljava/util/ArrayList;

    .line 221
    .line 222
    move/from16 v17, v13

    .line 223
    .line 224
    const/4 v13, 0x0

    .line 225
    move/from16 v18, v17

    .line 226
    .line 227
    const/16 v17, 0x0

    .line 228
    .line 229
    move/from16 v19, v18

    .line 230
    .line 231
    const/16 v18, 0x0

    .line 232
    .line 233
    move/from16 v20, v19

    .line 234
    .line 235
    const/16 v19, 0x0

    .line 236
    .line 237
    iget-object v2, v0, Lla/s;->e:Ljava/util/ArrayList;

    .line 238
    .line 239
    iget-object v10, v0, Lla/s;->o:Ljava/util/ArrayList;

    .line 240
    .line 241
    move/from16 v21, v20

    .line 242
    .line 243
    move-object/from16 v20, v2

    .line 244
    .line 245
    move/from16 v2, v21

    .line 246
    .line 247
    move-object/from16 v21, v10

    .line 248
    .line 249
    move-object v10, v1

    .line 250
    const/4 v1, 0x0

    .line 251
    invoke-direct/range {v3 .. v24}, Lla/b;-><init>(Landroid/content/Context;Ljava/lang/String;Landroidx/sqlite/db/a;Lfb/k;Ljava/util/List;ZLla/t;Ljava/util/concurrent/Executor;Ljava/util/concurrent/Executor;Landroid/content/Intent;ZZLjava/util/Set;Ljava/lang/String;Ljava/io/File;Ljava/util/concurrent/Callable;Ljava/util/List;Ljava/util/List;ZLua/b;Lpx0/g;)V

    .line 252
    .line 253
    .line 254
    iget-boolean v4, v0, Lla/s;->s:Z

    .line 255
    .line 256
    iput-boolean v4, v3, Lla/b;->v:Z

    .line 257
    .line 258
    iget-object v0, v0, Lla/s;->a:Lhy0/d;

    .line 259
    .line 260
    invoke-static {v0}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 261
    .line 262
    .line 263
    move-result-object v4

    .line 264
    invoke-virtual {v4}, Ljava/lang/Class;->getPackage()Ljava/lang/Package;

    .line 265
    .line 266
    .line 267
    move-result-object v0

    .line 268
    if-eqz v0, :cond_c

    .line 269
    .line 270
    invoke-virtual {v0}, Ljava/lang/Package;->getName()Ljava/lang/String;

    .line 271
    .line 272
    .line 273
    move-result-object v0

    .line 274
    if-nez v0, :cond_d

    .line 275
    .line 276
    :cond_c
    const-string v0, ""

    .line 277
    .line 278
    :cond_d
    invoke-virtual {v4}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 279
    .line 280
    .line 281
    move-result-object v5

    .line 282
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 283
    .line 284
    .line 285
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 286
    .line 287
    .line 288
    move-result v6

    .line 289
    if-nez v6, :cond_e

    .line 290
    .line 291
    goto :goto_5

    .line 292
    :cond_e
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 293
    .line 294
    .line 295
    move-result v6

    .line 296
    add-int/2addr v6, v2

    .line 297
    invoke-virtual {v5, v6}, Ljava/lang/String;->substring(I)Ljava/lang/String;

    .line 298
    .line 299
    .line 300
    move-result-object v5

    .line 301
    const-string v6, "substring(...)"

    .line 302
    .line 303
    invoke-static {v5, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 304
    .line 305
    .line 306
    :goto_5
    const/16 v6, 0x5f

    .line 307
    .line 308
    const/16 v7, 0x2e

    .line 309
    .line 310
    invoke-static {v5, v7, v6}, Lly0/w;->u(Ljava/lang/String;CC)Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object v5

    .line 314
    const-string v6, "_Impl"

    .line 315
    .line 316
    invoke-virtual {v5, v6}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 317
    .line 318
    .line 319
    move-result-object v5

    .line 320
    :try_start_0
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 321
    .line 322
    .line 323
    move-result v6

    .line 324
    if-nez v6, :cond_f

    .line 325
    .line 326
    move-object v0, v5

    .line 327
    goto :goto_6

    .line 328
    :cond_f
    new-instance v6, Ljava/lang/StringBuilder;

    .line 329
    .line 330
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    .line 331
    .line 332
    .line 333
    invoke-virtual {v6, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 334
    .line 335
    .line 336
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 337
    .line 338
    .line 339
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 340
    .line 341
    .line 342
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 343
    .line 344
    .line 345
    move-result-object v0

    .line 346
    :goto_6
    invoke-virtual {v4}, Ljava/lang/Class;->getClassLoader()Ljava/lang/ClassLoader;

    .line 347
    .line 348
    .line 349
    move-result-object v6

    .line 350
    invoke-static {v0, v2, v6}, Ljava/lang/Class;->forName(Ljava/lang/String;ZLjava/lang/ClassLoader;)Ljava/lang/Class;

    .line 351
    .line 352
    .line 353
    move-result-object v0

    .line 354
    const-string v6, "null cannot be cast to non-null type java.lang.Class<T of androidx.room.util.KClassUtil.findAndInstantiateDatabaseImpl>"

    .line 355
    .line 356
    invoke-static {v0, v6}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 357
    .line 358
    .line 359
    invoke-virtual {v0, v1}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 360
    .line 361
    .line 362
    move-result-object v0

    .line 363
    invoke-virtual {v0, v1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 364
    .line 365
    .line 366
    move-result-object v0
    :try_end_0
    .catch Ljava/lang/ClassNotFoundException; {:try_start_0 .. :try_end_0} :catch_3
    .catch Ljava/lang/IllegalAccessException; {:try_start_0 .. :try_end_0} :catch_2
    .catch Ljava/lang/InstantiationException; {:try_start_0 .. :try_end_0} :catch_1

    .line 367
    move-object v6, v0

    .line 368
    check-cast v6, Lla/u;

    .line 369
    .line 370
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 371
    .line 372
    .line 373
    iget-boolean v0, v3, Lla/b;->v:Z

    .line 374
    .line 375
    iput-boolean v0, v6, Lla/u;->k:Z

    .line 376
    .line 377
    :try_start_1
    invoke-virtual {v6}, Lla/u;->f()Lka/u;

    .line 378
    .line 379
    .line 380
    move-result-object v10

    .line 381
    const-string v0, "null cannot be cast to non-null type androidx.room.RoomOpenDelegate"

    .line 382
    .line 383
    invoke-static {v10, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_1
    .catch Llx0/k; {:try_start_1 .. :try_end_1} :catch_0

    .line 384
    .line 385
    .line 386
    move-object v0, v10

    .line 387
    goto :goto_7

    .line 388
    :catch_0
    move-object v0, v1

    .line 389
    :goto_7
    if-eqz v0, :cond_2f

    .line 390
    .line 391
    new-instance v12, Lla/r;

    .line 392
    .line 393
    new-instance v4, Ljd/b;

    .line 394
    .line 395
    const/4 v10, 0x1

    .line 396
    const/4 v11, 0x3

    .line 397
    const/4 v5, 0x2

    .line 398
    const-class v7, Lla/w;

    .line 399
    .line 400
    const-string v8, "compatTransactionCoroutineExecute"

    .line 401
    .line 402
    const-string v9, "compatTransactionCoroutineExecute(Landroidx/room/RoomDatabase;Lkotlin/jvm/functions/Function1;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 403
    .line 404
    invoke-direct/range {v4 .. v11}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 405
    .line 406
    .line 407
    invoke-direct {v12, v3, v0, v4}, Lla/r;-><init>(Lla/b;Lka/u;Ljd/b;)V

    .line 408
    .line 409
    .line 410
    iput-object v12, v6, Lla/u;->e:Lla/r;

    .line 411
    .line 412
    invoke-virtual {v6}, Lla/u;->e()Lla/h;

    .line 413
    .line 414
    .line 415
    move-result-object v0

    .line 416
    iput-object v0, v6, Lla/u;->f:Lla/h;

    .line 417
    .line 418
    new-instance v0, Ljava/util/LinkedHashMap;

    .line 419
    .line 420
    invoke-direct {v0}, Ljava/util/LinkedHashMap;-><init>()V

    .line 421
    .line 422
    .line 423
    invoke-virtual {v6}, Lla/u;->j()Ljava/util/Set;

    .line 424
    .line 425
    .line 426
    move-result-object v4

    .line 427
    iget-object v5, v3, Lla/b;->r:Ljava/util/List;

    .line 428
    .line 429
    invoke-interface {v5}, Ljava/util/List;->size()I

    .line 430
    .line 431
    .line 432
    move-result v7

    .line 433
    new-array v8, v7, [Z

    .line 434
    .line 435
    invoke-interface {v4}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 436
    .line 437
    .line 438
    move-result-object v4

    .line 439
    :goto_8
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 440
    .line 441
    .line 442
    move-result v9

    .line 443
    const/4 v10, -0x1

    .line 444
    if-eqz v9, :cond_14

    .line 445
    .line 446
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 447
    .line 448
    .line 449
    move-result-object v9

    .line 450
    check-cast v9, Lhy0/d;

    .line 451
    .line 452
    move-object v11, v5

    .line 453
    check-cast v11, Ljava/util/Collection;

    .line 454
    .line 455
    invoke-interface {v11}, Ljava/util/Collection;->size()I

    .line 456
    .line 457
    .line 458
    move-result v11

    .line 459
    add-int/2addr v11, v10

    .line 460
    if-ltz v11, :cond_12

    .line 461
    .line 462
    :goto_9
    add-int/lit8 v12, v11, -0x1

    .line 463
    .line 464
    invoke-interface {v5, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 465
    .line 466
    .line 467
    move-result-object v13

    .line 468
    invoke-interface {v9, v13}, Lhy0/d;->isInstance(Ljava/lang/Object;)Z

    .line 469
    .line 470
    .line 471
    move-result v13

    .line 472
    if-eqz v13, :cond_10

    .line 473
    .line 474
    aput-boolean v2, v8, v11

    .line 475
    .line 476
    move v10, v11

    .line 477
    goto :goto_a

    .line 478
    :cond_10
    if-gez v12, :cond_11

    .line 479
    .line 480
    goto :goto_a

    .line 481
    :cond_11
    move v11, v12

    .line 482
    goto :goto_9

    .line 483
    :cond_12
    :goto_a
    if-ltz v10, :cond_13

    .line 484
    .line 485
    invoke-interface {v5, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 486
    .line 487
    .line 488
    move-result-object v10

    .line 489
    invoke-interface {v0, v9, v10}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 490
    .line 491
    .line 492
    goto :goto_8

    .line 493
    :cond_13
    new-instance v0, Ljava/lang/StringBuilder;

    .line 494
    .line 495
    const-string v1, "A required auto migration spec ("

    .line 496
    .line 497
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 498
    .line 499
    .line 500
    invoke-interface {v9}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 501
    .line 502
    .line 503
    move-result-object v1

    .line 504
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 505
    .line 506
    .line 507
    const-string v1, ") is missing in the database configuration."

    .line 508
    .line 509
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 510
    .line 511
    .line 512
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 513
    .line 514
    .line 515
    move-result-object v0

    .line 516
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 517
    .line 518
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 519
    .line 520
    .line 521
    move-result-object v0

    .line 522
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 523
    .line 524
    .line 525
    throw v1

    .line 526
    :cond_14
    check-cast v5, Ljava/util/Collection;

    .line 527
    .line 528
    invoke-interface {v5}, Ljava/util/Collection;->size()I

    .line 529
    .line 530
    .line 531
    move-result v4

    .line 532
    add-int/2addr v4, v10

    .line 533
    if-ltz v4, :cond_17

    .line 534
    .line 535
    :goto_b
    add-int/lit8 v5, v4, -0x1

    .line 536
    .line 537
    if-ge v4, v7, :cond_16

    .line 538
    .line 539
    aget-boolean v4, v8, v4

    .line 540
    .line 541
    if-eqz v4, :cond_16

    .line 542
    .line 543
    if-gez v5, :cond_15

    .line 544
    .line 545
    goto :goto_c

    .line 546
    :cond_15
    move v4, v5

    .line 547
    goto :goto_b

    .line 548
    :cond_16
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 549
    .line 550
    const-string v1, "Unexpected auto migration specs found. Annotate AutoMigrationSpec implementation with @ProvidedAutoMigrationSpec annotation or remove this spec from the builder."

    .line 551
    .line 552
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 553
    .line 554
    .line 555
    throw v0

    .line 556
    :cond_17
    :goto_c
    invoke-virtual {v6, v0}, Lla/u;->d(Ljava/util/LinkedHashMap;)Ljava/util/List;

    .line 557
    .line 558
    .line 559
    move-result-object v0

    .line 560
    invoke-interface {v0}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 561
    .line 562
    .line 563
    move-result-object v0

    .line 564
    :cond_18
    :goto_d
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 565
    .line 566
    .line 567
    move-result v4

    .line 568
    if-eqz v4, :cond_1b

    .line 569
    .line 570
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 571
    .line 572
    .line 573
    move-result-object v4

    .line 574
    check-cast v4, Loa/b;

    .line 575
    .line 576
    iget v5, v4, Loa/b;->a:I

    .line 577
    .line 578
    iget v7, v4, Loa/b;->b:I

    .line 579
    .line 580
    iget-object v8, v3, Lla/b;->d:Lfb/k;

    .line 581
    .line 582
    iget-object v9, v8, Lfb/k;->a:Ljava/util/LinkedHashMap;

    .line 583
    .line 584
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 585
    .line 586
    .line 587
    move-result-object v11

    .line 588
    invoke-interface {v9, v11}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 589
    .line 590
    .line 591
    move-result v11

    .line 592
    if-eqz v11, :cond_1a

    .line 593
    .line 594
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 595
    .line 596
    .line 597
    move-result-object v5

    .line 598
    invoke-virtual {v9, v5}, Ljava/util/LinkedHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 599
    .line 600
    .line 601
    move-result-object v5

    .line 602
    check-cast v5, Ljava/util/Map;

    .line 603
    .line 604
    if-nez v5, :cond_19

    .line 605
    .line 606
    sget-object v5, Lmx0/t;->d:Lmx0/t;

    .line 607
    .line 608
    :cond_19
    invoke-static {v7}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 609
    .line 610
    .line 611
    move-result-object v7

    .line 612
    invoke-interface {v5, v7}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 613
    .line 614
    .line 615
    move-result v5

    .line 616
    goto :goto_e

    .line 617
    :cond_1a
    const/4 v5, 0x0

    .line 618
    :goto_e
    if-nez v5, :cond_18

    .line 619
    .line 620
    invoke-virtual {v8, v4}, Lfb/k;->c(Loa/b;)V

    .line 621
    .line 622
    .line 623
    goto :goto_d

    .line 624
    :cond_1b
    invoke-virtual {v6}, Lla/u;->k()Ljava/util/LinkedHashMap;

    .line 625
    .line 626
    .line 627
    move-result-object v0

    .line 628
    iget-object v4, v3, Lla/b;->q:Ljava/util/List;

    .line 629
    .line 630
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 631
    .line 632
    .line 633
    move-result v5

    .line 634
    new-array v5, v5, [Z

    .line 635
    .line 636
    invoke-virtual {v0}, Ljava/util/LinkedHashMap;->entrySet()Ljava/util/Set;

    .line 637
    .line 638
    .line 639
    move-result-object v0

    .line 640
    invoke-interface {v0}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 641
    .line 642
    .line 643
    move-result-object v0

    .line 644
    :cond_1c
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 645
    .line 646
    .line 647
    move-result v7

    .line 648
    if-eqz v7, :cond_21

    .line 649
    .line 650
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 651
    .line 652
    .line 653
    move-result-object v7

    .line 654
    check-cast v7, Ljava/util/Map$Entry;

    .line 655
    .line 656
    invoke-interface {v7}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 657
    .line 658
    .line 659
    move-result-object v8

    .line 660
    check-cast v8, Lhy0/d;

    .line 661
    .line 662
    invoke-interface {v7}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 663
    .line 664
    .line 665
    move-result-object v7

    .line 666
    check-cast v7, Ljava/util/List;

    .line 667
    .line 668
    invoke-interface {v7}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 669
    .line 670
    .line 671
    move-result-object v7

    .line 672
    :goto_f
    invoke-interface {v7}, Ljava/util/Iterator;->hasNext()Z

    .line 673
    .line 674
    .line 675
    move-result v9

    .line 676
    if-eqz v9, :cond_1c

    .line 677
    .line 678
    invoke-interface {v7}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 679
    .line 680
    .line 681
    move-result-object v9

    .line 682
    check-cast v9, Lhy0/d;

    .line 683
    .line 684
    move-object v11, v4

    .line 685
    check-cast v11, Ljava/util/Collection;

    .line 686
    .line 687
    invoke-interface {v11}, Ljava/util/Collection;->size()I

    .line 688
    .line 689
    .line 690
    move-result v11

    .line 691
    add-int/2addr v11, v10

    .line 692
    if-ltz v11, :cond_1f

    .line 693
    .line 694
    :goto_10
    add-int/lit8 v12, v11, -0x1

    .line 695
    .line 696
    invoke-interface {v4, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 697
    .line 698
    .line 699
    move-result-object v13

    .line 700
    invoke-interface {v9, v13}, Lhy0/d;->isInstance(Ljava/lang/Object;)Z

    .line 701
    .line 702
    .line 703
    move-result v13

    .line 704
    if-eqz v13, :cond_1d

    .line 705
    .line 706
    aput-boolean v2, v5, v11

    .line 707
    .line 708
    goto :goto_12

    .line 709
    :cond_1d
    if-gez v12, :cond_1e

    .line 710
    .line 711
    goto :goto_11

    .line 712
    :cond_1e
    move v11, v12

    .line 713
    goto :goto_10

    .line 714
    :cond_1f
    :goto_11
    move v11, v10

    .line 715
    :goto_12
    if-ltz v11, :cond_20

    .line 716
    .line 717
    invoke-interface {v4, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 718
    .line 719
    .line 720
    move-result-object v11

    .line 721
    const-string v12, "kclass"

    .line 722
    .line 723
    invoke-static {v9, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 724
    .line 725
    .line 726
    const-string v12, "converter"

    .line 727
    .line 728
    invoke-static {v11, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 729
    .line 730
    .line 731
    iget-object v12, v6, Lla/u;->j:Ljava/util/LinkedHashMap;

    .line 732
    .line 733
    invoke-interface {v12, v9, v11}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 734
    .line 735
    .line 736
    goto :goto_f

    .line 737
    :cond_20
    new-instance v0, Ljava/lang/StringBuilder;

    .line 738
    .line 739
    const-string v1, "A required type converter ("

    .line 740
    .line 741
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 742
    .line 743
    .line 744
    invoke-interface {v9}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 745
    .line 746
    .line 747
    move-result-object v1

    .line 748
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 749
    .line 750
    .line 751
    const-string v1, ") for "

    .line 752
    .line 753
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 754
    .line 755
    .line 756
    invoke-interface {v8}, Lhy0/d;->getQualifiedName()Ljava/lang/String;

    .line 757
    .line 758
    .line 759
    move-result-object v1

    .line 760
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 761
    .line 762
    .line 763
    const-string v1, " is missing in the database configuration."

    .line 764
    .line 765
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 766
    .line 767
    .line 768
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 769
    .line 770
    .line 771
    move-result-object v0

    .line 772
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 773
    .line 774
    invoke-virtual {v0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 775
    .line 776
    .line 777
    move-result-object v0

    .line 778
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 779
    .line 780
    .line 781
    throw v1

    .line 782
    :cond_21
    move-object v0, v4

    .line 783
    check-cast v0, Ljava/util/Collection;

    .line 784
    .line 785
    invoke-interface {v0}, Ljava/util/Collection;->size()I

    .line 786
    .line 787
    .line 788
    move-result v0

    .line 789
    add-int/2addr v0, v10

    .line 790
    if-ltz v0, :cond_24

    .line 791
    .line 792
    :goto_13
    add-int/lit8 v2, v0, -0x1

    .line 793
    .line 794
    aget-boolean v7, v5, v0

    .line 795
    .line 796
    if-eqz v7, :cond_23

    .line 797
    .line 798
    if-gez v2, :cond_22

    .line 799
    .line 800
    goto :goto_14

    .line 801
    :cond_22
    move v0, v2

    .line 802
    goto :goto_13

    .line 803
    :cond_23
    invoke-interface {v4, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 804
    .line 805
    .line 806
    move-result-object v0

    .line 807
    new-instance v1, Ljava/lang/IllegalArgumentException;

    .line 808
    .line 809
    const-string v2, "Unexpected type converter "

    .line 810
    .line 811
    const-string v3, ". Annotate TypeConverter class with @ProvidedTypeConverter annotation or remove this converter from the builder."

    .line 812
    .line 813
    invoke-static {v0, v2, v3}, Lf2/m0;->g(Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 814
    .line 815
    .line 816
    move-result-object v0

    .line 817
    invoke-direct {v1, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 818
    .line 819
    .line 820
    throw v1

    .line 821
    :cond_24
    :goto_14
    iget-object v0, v3, Lla/b;->h:Ljava/util/concurrent/Executor;

    .line 822
    .line 823
    iput-object v0, v6, Lla/u;->c:Ljava/util/concurrent/Executor;

    .line 824
    .line 825
    new-instance v0, Lla/a0;

    .line 826
    .line 827
    iget-object v2, v3, Lla/b;->i:Ljava/util/concurrent/Executor;

    .line 828
    .line 829
    const/4 v4, 0x0

    .line 830
    invoke-direct {v0, v2, v4}, Lla/a0;-><init>(Ljava/util/concurrent/Executor;I)V

    .line 831
    .line 832
    .line 833
    iput-object v0, v6, Lla/u;->d:Lla/a0;

    .line 834
    .line 835
    iget-object v0, v6, Lla/u;->c:Ljava/util/concurrent/Executor;

    .line 836
    .line 837
    if-eqz v0, :cond_2e

    .line 838
    .line 839
    invoke-static {v0}, Lvy0/e0;->t(Ljava/util/concurrent/Executor;)Lvy0/x;

    .line 840
    .line 841
    .line 842
    move-result-object v0

    .line 843
    invoke-static {}, Lvy0/e0;->f()Lvy0/z1;

    .line 844
    .line 845
    .line 846
    move-result-object v2

    .line 847
    invoke-virtual {v0, v2}, Lpx0/a;->plus(Lpx0/g;)Lpx0/g;

    .line 848
    .line 849
    .line 850
    move-result-object v0

    .line 851
    invoke-static {v0}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 852
    .line 853
    .line 854
    move-result-object v0

    .line 855
    iput-object v0, v6, Lla/u;->a:Lpw0/a;

    .line 856
    .line 857
    iget-object v0, v0, Lpw0/a;->e:Lpx0/g;

    .line 858
    .line 859
    iget-object v2, v6, Lla/u;->d:Lla/a0;

    .line 860
    .line 861
    if-eqz v2, :cond_2d

    .line 862
    .line 863
    invoke-static {v2}, Lvy0/e0;->t(Ljava/util/concurrent/Executor;)Lvy0/x;

    .line 864
    .line 865
    .line 866
    move-result-object v2

    .line 867
    invoke-interface {v0, v2}, Lpx0/g;->plus(Lpx0/g;)Lpx0/g;

    .line 868
    .line 869
    .line 870
    move-result-object v0

    .line 871
    iput-object v0, v6, Lla/u;->b:Lpx0/g;

    .line 872
    .line 873
    iget-boolean v0, v3, Lla/b;->f:Z

    .line 874
    .line 875
    iput-boolean v0, v6, Lla/u;->h:Z

    .line 876
    .line 877
    iget-object v0, v6, Lla/u;->e:Lla/r;

    .line 878
    .line 879
    const-string v2, "connectionManager"

    .line 880
    .line 881
    if-eqz v0, :cond_2c

    .line 882
    .line 883
    iget-object v0, v0, Lla/r;->g:Landroidx/sqlite/db/SupportSQLiteOpenHelper;

    .line 884
    .line 885
    if-nez v0, :cond_26

    .line 886
    .line 887
    :cond_25
    move-object v10, v1

    .line 888
    goto :goto_16

    .line 889
    :cond_26
    move-object v10, v0

    .line 890
    :goto_15
    instance-of v0, v10, Lpa/b;

    .line 891
    .line 892
    if-eqz v0, :cond_27

    .line 893
    .line 894
    goto :goto_16

    .line 895
    :cond_27
    instance-of v0, v10, Lla/c;

    .line 896
    .line 897
    if-eqz v0, :cond_25

    .line 898
    .line 899
    check-cast v10, Lla/c;

    .line 900
    .line 901
    invoke-interface {v10}, Lla/c;->getDelegate()Landroidx/sqlite/db/SupportSQLiteOpenHelper;

    .line 902
    .line 903
    .line 904
    move-result-object v10

    .line 905
    goto :goto_15

    .line 906
    :goto_16
    check-cast v10, Lpa/b;

    .line 907
    .line 908
    iget-object v0, v6, Lla/u;->e:Lla/r;

    .line 909
    .line 910
    if-eqz v0, :cond_2b

    .line 911
    .line 912
    iget-object v0, v0, Lla/r;->g:Landroidx/sqlite/db/SupportSQLiteOpenHelper;

    .line 913
    .line 914
    if-nez v0, :cond_29

    .line 915
    .line 916
    :cond_28
    move-object v10, v1

    .line 917
    goto :goto_18

    .line 918
    :cond_29
    move-object v10, v0

    .line 919
    :goto_17
    instance-of v0, v10, Lpa/a;

    .line 920
    .line 921
    if-eqz v0, :cond_2a

    .line 922
    .line 923
    goto :goto_18

    .line 924
    :cond_2a
    instance-of v0, v10, Lla/c;

    .line 925
    .line 926
    if-eqz v0, :cond_28

    .line 927
    .line 928
    check-cast v10, Lla/c;

    .line 929
    .line 930
    invoke-interface {v10}, Lla/c;->getDelegate()Landroidx/sqlite/db/SupportSQLiteOpenHelper;

    .line 931
    .line 932
    .line 933
    move-result-object v10

    .line 934
    goto :goto_17

    .line 935
    :goto_18
    check-cast v10, Lpa/a;

    .line 936
    .line 937
    return-object v6

    .line 938
    :cond_2b
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 939
    .line 940
    .line 941
    throw v1

    .line 942
    :cond_2c
    invoke-static {v2}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 943
    .line 944
    .line 945
    throw v1

    .line 946
    :cond_2d
    const-string v0, "internalTransactionExecutor"

    .line 947
    .line 948
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 949
    .line 950
    .line 951
    throw v1

    .line 952
    :cond_2e
    const-string v0, "internalQueryExecutor"

    .line 953
    .line 954
    invoke-static {v0}, Lkotlin/jvm/internal/m;->n(Ljava/lang/String;)V

    .line 955
    .line 956
    .line 957
    throw v1

    .line 958
    :cond_2f
    new-instance v0, Lla/r;

    .line 959
    .line 960
    new-instance v2, Lkq0/a;

    .line 961
    .line 962
    const/16 v4, 0x8

    .line 963
    .line 964
    invoke-direct {v2, v6, v4}, Lkq0/a;-><init>(Ljava/lang/Object;I)V

    .line 965
    .line 966
    .line 967
    new-instance v4, Ljd/b;

    .line 968
    .line 969
    const/4 v10, 0x1

    .line 970
    const/4 v11, 0x2

    .line 971
    const/4 v5, 0x2

    .line 972
    const-class v7, Lla/w;

    .line 973
    .line 974
    const-string v8, "compatTransactionCoroutineExecute"

    .line 975
    .line 976
    const-string v9, "compatTransactionCoroutineExecute(Landroidx/room/RoomDatabase;Lkotlin/jvm/functions/Function1;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;"

    .line 977
    .line 978
    invoke-direct/range {v4 .. v11}, Ljd/b;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 979
    .line 980
    .line 981
    invoke-direct {v0, v3, v2, v4}, Lla/r;-><init>(Lla/b;Lkq0/a;Ljd/b;)V

    .line 982
    .line 983
    .line 984
    throw v1

    .line 985
    :catch_1
    move-exception v0

    .line 986
    goto :goto_19

    .line 987
    :catch_2
    move-exception v0

    .line 988
    goto :goto_1a

    .line 989
    :catch_3
    move-exception v0

    .line 990
    goto :goto_1b

    .line 991
    :goto_19
    new-instance v1, Ljava/lang/RuntimeException;

    .line 992
    .line 993
    new-instance v2, Ljava/lang/StringBuilder;

    .line 994
    .line 995
    const-string v3, "Failed to create an instance of "

    .line 996
    .line 997
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 998
    .line 999
    .line 1000
    invoke-virtual {v4}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 1001
    .line 1002
    .line 1003
    move-result-object v3

    .line 1004
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1005
    .line 1006
    .line 1007
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1008
    .line 1009
    .line 1010
    move-result-object v2

    .line 1011
    invoke-direct {v1, v2, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 1012
    .line 1013
    .line 1014
    throw v1

    .line 1015
    :goto_1a
    new-instance v1, Ljava/lang/RuntimeException;

    .line 1016
    .line 1017
    new-instance v2, Ljava/lang/StringBuilder;

    .line 1018
    .line 1019
    const-string v3, "Cannot access the constructor "

    .line 1020
    .line 1021
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1022
    .line 1023
    .line 1024
    invoke-virtual {v4}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 1025
    .line 1026
    .line 1027
    move-result-object v3

    .line 1028
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1029
    .line 1030
    .line 1031
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1032
    .line 1033
    .line 1034
    move-result-object v2

    .line 1035
    invoke-direct {v1, v2, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 1036
    .line 1037
    .line 1038
    throw v1

    .line 1039
    :goto_1b
    new-instance v1, Ljava/lang/RuntimeException;

    .line 1040
    .line 1041
    new-instance v2, Ljava/lang/StringBuilder;

    .line 1042
    .line 1043
    const-string v3, "Cannot find implementation for "

    .line 1044
    .line 1045
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 1046
    .line 1047
    .line 1048
    invoke-virtual {v4}, Ljava/lang/Class;->getCanonicalName()Ljava/lang/String;

    .line 1049
    .line 1050
    .line 1051
    move-result-object v3

    .line 1052
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1053
    .line 1054
    .line 1055
    const-string v3, ". "

    .line 1056
    .line 1057
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1058
    .line 1059
    .line 1060
    invoke-virtual {v2, v5}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1061
    .line 1062
    .line 1063
    const-string v3, " does not exist. Is Room annotation processor correctly configured?"

    .line 1064
    .line 1065
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 1066
    .line 1067
    .line 1068
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 1069
    .line 1070
    .line 1071
    move-result-object v2

    .line 1072
    invoke-direct {v1, v2, v0}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 1073
    .line 1074
    .line 1075
    throw v1

    .line 1076
    :cond_30
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1077
    .line 1078
    invoke-direct {v0, v5}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1079
    .line 1080
    .line 1081
    throw v0

    .line 1082
    :cond_31
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 1083
    .line 1084
    invoke-direct {v0, v5}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 1085
    .line 1086
    .line 1087
    throw v0
.end method
