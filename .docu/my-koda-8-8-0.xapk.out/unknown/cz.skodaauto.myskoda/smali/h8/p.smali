.class public final Lh8/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh8/a0;


# instance fields
.field public final a:Lh8/o;

.field public final b:Ly7/k;

.field public c:Lwe0/b;

.field public final d:J

.field public final e:J

.field public final f:J

.field public final g:F

.field public final h:F

.field public i:Z


# direct methods
.method public constructor <init>(Landroid/content/Context;Lo8/m;)V
    .locals 2

    .line 1
    new-instance v0, Ly7/k;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Ly7/k;-><init>(Landroid/content/Context;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object v0, p0, Lh8/p;->b:Ly7/k;

    .line 10
    .line 11
    new-instance p1, Lwe0/b;

    .line 12
    .line 13
    const/16 v1, 0x8

    .line 14
    .line 15
    invoke-direct {p1, v1}, Lwe0/b;-><init>(I)V

    .line 16
    .line 17
    .line 18
    iput-object p1, p0, Lh8/p;->c:Lwe0/b;

    .line 19
    .line 20
    new-instance v1, Lh8/o;

    .line 21
    .line 22
    invoke-direct {v1, p2, p1}, Lh8/o;-><init>(Lo8/m;Lwe0/b;)V

    .line 23
    .line 24
    .line 25
    iput-object v1, p0, Lh8/p;->a:Lh8/o;

    .line 26
    .line 27
    iget-object p1, v1, Lh8/o;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast p1, Ly7/k;

    .line 30
    .line 31
    if-eq v0, p1, :cond_0

    .line 32
    .line 33
    iput-object v0, v1, Lh8/o;->e:Ljava/lang/Object;

    .line 34
    .line 35
    iget-object p1, v1, Lh8/o;->c:Ljava/lang/Object;

    .line 36
    .line 37
    check-cast p1, Ljava/util/HashMap;

    .line 38
    .line 39
    invoke-virtual {p1}, Ljava/util/HashMap;->clear()V

    .line 40
    .line 41
    .line 42
    iget-object p1, v1, Lh8/o;->d:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast p1, Ljava/util/HashMap;

    .line 45
    .line 46
    invoke-virtual {p1}, Ljava/util/HashMap;->clear()V

    .line 47
    .line 48
    .line 49
    :cond_0
    const-wide p1, -0x7fffffffffffffffL    # -4.9E-324

    .line 50
    .line 51
    .line 52
    .line 53
    .line 54
    iput-wide p1, p0, Lh8/p;->d:J

    .line 55
    .line 56
    iput-wide p1, p0, Lh8/p;->e:J

    .line 57
    .line 58
    iput-wide p1, p0, Lh8/p;->f:J

    .line 59
    .line 60
    const p1, -0x800001

    .line 61
    .line 62
    .line 63
    iput p1, p0, Lh8/p;->g:F

    .line 64
    .line 65
    iput p1, p0, Lh8/p;->h:F

    .line 66
    .line 67
    const/4 p1, 0x1

    .line 68
    iput-boolean p1, p0, Lh8/p;->i:Z

    .line 69
    .line 70
    return-void
.end method

.method public static e(Ljava/lang/Class;Ly7/g;)Lh8/a0;
    .locals 1

    .line 1
    :try_start_0
    const-class v0, Ly7/g;

    .line 2
    .line 3
    filled-new-array {v0}, [Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p0, v0}, Ljava/lang/Class;->getConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    filled-new-array {p1}, [Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p1

    .line 15
    invoke-virtual {p0, p1}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Lh8/a0;
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 20
    .line 21
    return-object p0

    .line 22
    :catch_0
    move-exception p0

    .line 23
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/Throwable;)V

    .line 26
    .line 27
    .line 28
    throw p1
.end method


# virtual methods
.method public final a(Lwe0/b;)V
    .locals 1

    .line 1
    iput-object p1, p0, Lh8/p;->c:Lwe0/b;

    .line 2
    .line 3
    iget-object p0, p0, Lh8/p;->a:Lh8/o;

    .line 4
    .line 5
    iput-object p1, p0, Lh8/o;->f:Ljava/lang/Object;

    .line 6
    .line 7
    iget-object v0, p0, Lh8/o;->b:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lo8/m;

    .line 10
    .line 11
    monitor-enter v0

    .line 12
    :try_start_0
    iput-object p1, v0, Lo8/m;->f:Lwe0/b;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    .line 14
    monitor-exit v0

    .line 15
    iget-object p0, p0, Lh8/o;->d:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Ljava/util/HashMap;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Lh8/a0;

    .line 38
    .line 39
    invoke-interface {v0, p1}, Lh8/a0;->a(Lwe0/b;)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    return-void

    .line 44
    :catchall_0
    move-exception p0

    .line 45
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 46
    throw p0
.end method

.method public final b(Lt7/x;)Lh8/a;
    .locals 24

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iget-object v2, v1, Lt7/x;->b:Lt7/u;

    .line 6
    .line 7
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    iget-object v2, v1, Lt7/x;->b:Lt7/u;

    .line 11
    .line 12
    iget-object v2, v2, Lt7/u;->a:Landroid/net/Uri;

    .line 13
    .line 14
    invoke-virtual {v2}, Landroid/net/Uri;->getScheme()Ljava/lang/String;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    const/4 v3, 0x0

    .line 19
    if-eqz v2, :cond_1

    .line 20
    .line 21
    const-string v4, "ssai"

    .line 22
    .line 23
    invoke-virtual {v2, v4}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    if-nez v2, :cond_0

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    throw v3

    .line 31
    :cond_1
    :goto_0
    iget-object v2, v1, Lt7/x;->b:Lt7/u;

    .line 32
    .line 33
    iget-object v2, v2, Lt7/u;->b:Ljava/lang/String;

    .line 34
    .line 35
    const-string v4, "application/x-image-uri"

    .line 36
    .line 37
    invoke-static {v2, v4}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v2

    .line 41
    if-nez v2, :cond_13

    .line 42
    .line 43
    iget-object v2, v1, Lt7/x;->b:Lt7/u;

    .line 44
    .line 45
    iget-object v4, v2, Lt7/u;->a:Landroid/net/Uri;

    .line 46
    .line 47
    iget-object v2, v2, Lt7/u;->b:Ljava/lang/String;

    .line 48
    .line 49
    invoke-static {v4, v2}, Lw7/w;->x(Landroid/net/Uri;Ljava/lang/String;)I

    .line 50
    .line 51
    .line 52
    move-result v2

    .line 53
    iget-object v4, v1, Lt7/x;->b:Lt7/u;

    .line 54
    .line 55
    iget-wide v4, v4, Lt7/u;->e:J

    .line 56
    .line 57
    const-wide v6, -0x7fffffffffffffffL    # -4.9E-324

    .line 58
    .line 59
    .line 60
    .line 61
    .line 62
    cmp-long v4, v4, v6

    .line 63
    .line 64
    const/4 v5, 0x1

    .line 65
    if-eqz v4, :cond_2

    .line 66
    .line 67
    iget-object v4, v0, Lh8/p;->a:Lh8/o;

    .line 68
    .line 69
    iget-object v4, v4, Lh8/o;->b:Ljava/lang/Object;

    .line 70
    .line 71
    check-cast v4, Lo8/m;

    .line 72
    .line 73
    monitor-enter v4

    .line 74
    :try_start_0
    iput v5, v4, Lo8/m;->g:I
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 75
    .line 76
    monitor-exit v4

    .line 77
    goto :goto_1

    .line 78
    :catchall_0
    move-exception v0

    .line 79
    :try_start_1
    monitor-exit v4
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 80
    throw v0

    .line 81
    :cond_2
    :goto_1
    :try_start_2
    iget-object v4, v0, Lh8/p;->a:Lh8/o;

    .line 82
    .line 83
    iget-object v8, v4, Lh8/o;->d:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v8, Ljava/util/HashMap;

    .line 86
    .line 87
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 88
    .line 89
    .line 90
    move-result-object v9

    .line 91
    invoke-virtual {v8, v9}, Ljava/util/HashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v9

    .line 95
    check-cast v9, Lh8/a0;

    .line 96
    .line 97
    if-eqz v9, :cond_3

    .line 98
    .line 99
    goto :goto_2

    .line 100
    :cond_3
    invoke-virtual {v4, v2}, Lh8/o;->b(I)Lgr/m;

    .line 101
    .line 102
    .line 103
    move-result-object v9

    .line 104
    invoke-interface {v9}, Lgr/m;->get()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v9

    .line 108
    check-cast v9, Lh8/a0;

    .line 109
    .line 110
    iget-object v10, v4, Lh8/o;->f:Ljava/lang/Object;

    .line 111
    .line 112
    check-cast v10, Lwe0/b;

    .line 113
    .line 114
    invoke-interface {v9, v10}, Lh8/a0;->a(Lwe0/b;)V

    .line 115
    .line 116
    .line 117
    iget-boolean v4, v4, Lh8/o;->a:Z

    .line 118
    .line 119
    invoke-interface {v9, v4}, Lh8/a0;->c(Z)V

    .line 120
    .line 121
    .line 122
    invoke-interface {v9}, Lh8/a0;->d()V

    .line 123
    .line 124
    .line 125
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 126
    .line 127
    .line 128
    move-result-object v2

    .line 129
    invoke-virtual {v8, v2, v9}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    :try_end_2
    .catch Ljava/lang/ClassNotFoundException; {:try_start_2 .. :try_end_2} :catch_0

    .line 130
    .line 131
    .line 132
    :goto_2
    iget-object v2, v1, Lt7/x;->c:Lt7/t;

    .line 133
    .line 134
    invoke-virtual {v2}, Lt7/t;->a()Lt7/s;

    .line 135
    .line 136
    .line 137
    move-result-object v2

    .line 138
    iget-object v4, v1, Lt7/x;->c:Lt7/t;

    .line 139
    .line 140
    iget-wide v10, v4, Lt7/t;->a:J

    .line 141
    .line 142
    cmp-long v8, v10, v6

    .line 143
    .line 144
    if-nez v8, :cond_4

    .line 145
    .line 146
    iget-wide v10, v0, Lh8/p;->d:J

    .line 147
    .line 148
    iput-wide v10, v2, Lt7/s;->a:J

    .line 149
    .line 150
    :cond_4
    iget v8, v4, Lt7/t;->d:F

    .line 151
    .line 152
    const v10, -0x800001

    .line 153
    .line 154
    .line 155
    cmpl-float v8, v8, v10

    .line 156
    .line 157
    if-nez v8, :cond_5

    .line 158
    .line 159
    iget v8, v0, Lh8/p;->g:F

    .line 160
    .line 161
    iput v8, v2, Lt7/s;->d:F

    .line 162
    .line 163
    :cond_5
    iget v8, v4, Lt7/t;->e:F

    .line 164
    .line 165
    cmpl-float v8, v8, v10

    .line 166
    .line 167
    if-nez v8, :cond_6

    .line 168
    .line 169
    iget v8, v0, Lh8/p;->h:F

    .line 170
    .line 171
    iput v8, v2, Lt7/s;->e:F

    .line 172
    .line 173
    :cond_6
    iget-wide v10, v4, Lt7/t;->b:J

    .line 174
    .line 175
    cmp-long v8, v10, v6

    .line 176
    .line 177
    if-nez v8, :cond_7

    .line 178
    .line 179
    iget-wide v10, v0, Lh8/p;->e:J

    .line 180
    .line 181
    iput-wide v10, v2, Lt7/s;->b:J

    .line 182
    .line 183
    :cond_7
    iget-wide v10, v4, Lt7/t;->c:J

    .line 184
    .line 185
    cmp-long v4, v10, v6

    .line 186
    .line 187
    if-nez v4, :cond_8

    .line 188
    .line 189
    iget-wide v10, v0, Lh8/p;->f:J

    .line 190
    .line 191
    iput-wide v10, v2, Lt7/s;->c:J

    .line 192
    .line 193
    :cond_8
    new-instance v4, Lt7/t;

    .line 194
    .line 195
    invoke-direct {v4, v2}, Lt7/t;-><init>(Lt7/s;)V

    .line 196
    .line 197
    .line 198
    iget-object v2, v1, Lt7/x;->c:Lt7/t;

    .line 199
    .line 200
    invoke-virtual {v4, v2}, Lt7/t;->equals(Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result v2

    .line 204
    if-nez v2, :cond_d

    .line 205
    .line 206
    new-instance v2, Lt7/x0;

    .line 207
    .line 208
    invoke-direct {v2}, Lt7/x0;-><init>()V

    .line 209
    .line 210
    .line 211
    sget-object v2, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 212
    .line 213
    sget-object v8, Lhr/x0;->h:Lhr/x0;

    .line 214
    .line 215
    sget-object v10, Lt7/v;->a:Lt7/v;

    .line 216
    .line 217
    iget-object v10, v1, Lt7/x;->e:Lt7/r;

    .line 218
    .line 219
    new-instance v11, Lo8/s;

    .line 220
    .line 221
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 222
    .line 223
    .line 224
    iget-wide v12, v10, Lt7/q;->a:J

    .line 225
    .line 226
    iput-wide v12, v11, Lo8/s;->a:J

    .line 227
    .line 228
    iget-object v10, v1, Lt7/x;->a:Ljava/lang/String;

    .line 229
    .line 230
    iget-object v12, v1, Lt7/x;->d:Lt7/a0;

    .line 231
    .line 232
    iget-object v13, v1, Lt7/x;->c:Lt7/t;

    .line 233
    .line 234
    invoke-virtual {v13}, Lt7/t;->a()Lt7/s;

    .line 235
    .line 236
    .line 237
    iget-object v13, v1, Lt7/x;->f:Lt7/v;

    .line 238
    .line 239
    iget-object v1, v1, Lt7/x;->b:Lt7/u;

    .line 240
    .line 241
    if-eqz v1, :cond_9

    .line 242
    .line 243
    iget-object v2, v1, Lt7/u;->b:Ljava/lang/String;

    .line 244
    .line 245
    iget-object v6, v1, Lt7/u;->a:Landroid/net/Uri;

    .line 246
    .line 247
    iget-object v7, v1, Lt7/u;->c:Ljava/util/List;

    .line 248
    .line 249
    iget-object v8, v1, Lt7/u;->d:Lhr/h0;

    .line 250
    .line 251
    new-instance v14, Lt7/x0;

    .line 252
    .line 253
    invoke-direct {v14}, Lt7/x0;-><init>()V

    .line 254
    .line 255
    .line 256
    iget-wide v14, v1, Lt7/u;->e:J

    .line 257
    .line 258
    move-object/from16 v18, v2

    .line 259
    .line 260
    move-object/from16 v17, v6

    .line 261
    .line 262
    move-object/from16 v20, v7

    .line 263
    .line 264
    move-wide/from16 v22, v14

    .line 265
    .line 266
    :goto_3
    move-object/from16 v21, v8

    .line 267
    .line 268
    goto :goto_4

    .line 269
    :cond_9
    move-object/from16 v20, v2

    .line 270
    .line 271
    move-object/from16 v17, v3

    .line 272
    .line 273
    move-object/from16 v18, v17

    .line 274
    .line 275
    move-wide/from16 v22, v6

    .line 276
    .line 277
    goto :goto_3

    .line 278
    :goto_4
    invoke-virtual {v4}, Lt7/t;->a()Lt7/s;

    .line 279
    .line 280
    .line 281
    move-result-object v1

    .line 282
    const/16 v19, 0x0

    .line 283
    .line 284
    if-eqz v17, :cond_a

    .line 285
    .line 286
    new-instance v16, Lt7/u;

    .line 287
    .line 288
    invoke-direct/range {v16 .. v23}, Lt7/u;-><init>(Landroid/net/Uri;Ljava/lang/String;Lkp/o9;Ljava/util/List;Lhr/h0;J)V

    .line 289
    .line 290
    .line 291
    move-object/from16 v17, v16

    .line 292
    .line 293
    goto :goto_5

    .line 294
    :cond_a
    move-object/from16 v17, v19

    .line 295
    .line 296
    :goto_5
    new-instance v14, Lt7/x;

    .line 297
    .line 298
    if-eqz v10, :cond_b

    .line 299
    .line 300
    :goto_6
    move-object v15, v10

    .line 301
    goto :goto_7

    .line 302
    :cond_b
    const-string v10, ""

    .line 303
    .line 304
    goto :goto_6

    .line 305
    :goto_7
    new-instance v2, Lt7/r;

    .line 306
    .line 307
    invoke-direct {v2, v11}, Lt7/q;-><init>(Lo8/s;)V

    .line 308
    .line 309
    .line 310
    new-instance v4, Lt7/t;

    .line 311
    .line 312
    invoke-direct {v4, v1}, Lt7/t;-><init>(Lt7/s;)V

    .line 313
    .line 314
    .line 315
    if-eqz v12, :cond_c

    .line 316
    .line 317
    :goto_8
    move-object/from16 v16, v2

    .line 318
    .line 319
    move-object/from16 v18, v4

    .line 320
    .line 321
    move-object/from16 v19, v12

    .line 322
    .line 323
    move-object/from16 v20, v13

    .line 324
    .line 325
    goto :goto_9

    .line 326
    :cond_c
    sget-object v12, Lt7/a0;->B:Lt7/a0;

    .line 327
    .line 328
    goto :goto_8

    .line 329
    :goto_9
    invoke-direct/range {v14 .. v20}, Lt7/x;-><init>(Ljava/lang/String;Lt7/r;Lt7/u;Lt7/t;Lt7/a0;Lt7/v;)V

    .line 330
    .line 331
    .line 332
    goto :goto_a

    .line 333
    :cond_d
    move-object v14, v1

    .line 334
    :goto_a
    invoke-interface {v9, v14}, Lh8/a0;->b(Lt7/x;)Lh8/a;

    .line 335
    .line 336
    .line 337
    move-result-object v1

    .line 338
    iget-object v2, v14, Lt7/x;->b:Lt7/u;

    .line 339
    .line 340
    iget-object v2, v2, Lt7/u;->d:Lhr/h0;

    .line 341
    .line 342
    invoke-interface {v2}, Ljava/util/List;->isEmpty()Z

    .line 343
    .line 344
    .line 345
    move-result v4

    .line 346
    if-nez v4, :cond_11

    .line 347
    .line 348
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 349
    .line 350
    .line 351
    move-result v4

    .line 352
    add-int/2addr v4, v5

    .line 353
    new-array v4, v4, [Lh8/a;

    .line 354
    .line 355
    const/4 v6, 0x0

    .line 356
    aput-object v1, v4, v6

    .line 357
    .line 358
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 359
    .line 360
    .line 361
    move-result v1

    .line 362
    if-lez v1, :cond_10

    .line 363
    .line 364
    iget-boolean v1, v0, Lh8/p;->i:Z

    .line 365
    .line 366
    if-eqz v1, :cond_f

    .line 367
    .line 368
    new-instance v1, Lt7/n;

    .line 369
    .line 370
    invoke-direct {v1}, Lt7/n;-><init>()V

    .line 371
    .line 372
    .line 373
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v4

    .line 377
    check-cast v4, Lt7/w;

    .line 378
    .line 379
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 380
    .line 381
    .line 382
    sget-object v4, Lt7/d0;->a:Ljava/util/ArrayList;

    .line 383
    .line 384
    iput-object v3, v1, Lt7/n;->m:Ljava/lang/String;

    .line 385
    .line 386
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 387
    .line 388
    .line 389
    move-result-object v4

    .line 390
    check-cast v4, Lt7/w;

    .line 391
    .line 392
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 393
    .line 394
    .line 395
    iput-object v3, v1, Lt7/n;->d:Ljava/lang/String;

    .line 396
    .line 397
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 398
    .line 399
    .line 400
    move-result-object v4

    .line 401
    check-cast v4, Lt7/w;

    .line 402
    .line 403
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 404
    .line 405
    .line 406
    iput v6, v1, Lt7/n;->e:I

    .line 407
    .line 408
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 409
    .line 410
    .line 411
    move-result-object v4

    .line 412
    check-cast v4, Lt7/w;

    .line 413
    .line 414
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 415
    .line 416
    .line 417
    iput v6, v1, Lt7/n;->f:I

    .line 418
    .line 419
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 420
    .line 421
    .line 422
    move-result-object v4

    .line 423
    check-cast v4, Lt7/w;

    .line 424
    .line 425
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 426
    .line 427
    .line 428
    iput-object v3, v1, Lt7/n;->b:Ljava/lang/String;

    .line 429
    .line 430
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 431
    .line 432
    .line 433
    move-result-object v4

    .line 434
    check-cast v4, Lt7/w;

    .line 435
    .line 436
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 437
    .line 438
    .line 439
    iput-object v3, v1, Lt7/n;->a:Ljava/lang/String;

    .line 440
    .line 441
    new-instance v4, Lt7/o;

    .line 442
    .line 443
    invoke-direct {v4, v1}, Lt7/o;-><init>(Lt7/n;)V

    .line 444
    .line 445
    .line 446
    new-instance v1, Ld8/c;

    .line 447
    .line 448
    invoke-direct {v1, v6}, Ld8/c;-><init>(I)V

    .line 449
    .line 450
    .line 451
    iget-object v1, v0, Lh8/p;->c:Lwe0/b;

    .line 452
    .line 453
    invoke-virtual {v1, v4}, Lwe0/b;->i(Lt7/o;)Z

    .line 454
    .line 455
    .line 456
    move-result v1

    .line 457
    if-eqz v1, :cond_e

    .line 458
    .line 459
    invoke-virtual {v4}, Lt7/o;->a()Lt7/n;

    .line 460
    .line 461
    .line 462
    move-result-object v1

    .line 463
    const-string v5, "application/x-media3-cues"

    .line 464
    .line 465
    invoke-static {v5}, Lt7/d0;->m(Ljava/lang/String;)Ljava/lang/String;

    .line 466
    .line 467
    .line 468
    move-result-object v5

    .line 469
    iput-object v5, v1, Lt7/n;->m:Ljava/lang/String;

    .line 470
    .line 471
    iget-object v5, v4, Lt7/o;->n:Ljava/lang/String;

    .line 472
    .line 473
    iput-object v5, v1, Lt7/n;->j:Ljava/lang/String;

    .line 474
    .line 475
    iget-object v0, v0, Lh8/p;->c:Lwe0/b;

    .line 476
    .line 477
    invoke-virtual {v0, v4}, Lwe0/b;->j(Lt7/o;)I

    .line 478
    .line 479
    .line 480
    move-result v0

    .line 481
    iput v0, v1, Lt7/n;->K:I

    .line 482
    .line 483
    new-instance v0, Lt7/o;

    .line 484
    .line 485
    invoke-direct {v0, v1}, Lt7/o;-><init>(Lt7/n;)V

    .line 486
    .line 487
    .line 488
    :cond_e
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 489
    .line 490
    .line 491
    move-result-object v0

    .line 492
    check-cast v0, Lt7/w;

    .line 493
    .line 494
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 495
    .line 496
    .line 497
    throw v3

    .line 498
    :cond_f
    iget-object v0, v0, Lh8/p;->b:Ly7/k;

    .line 499
    .line 500
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 501
    .line 502
    .line 503
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 504
    .line 505
    .line 506
    move-result-object v0

    .line 507
    check-cast v0, Lt7/w;

    .line 508
    .line 509
    new-instance v1, Ljava/util/ArrayList;

    .line 510
    .line 511
    invoke-direct {v1, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 512
    .line 513
    .line 514
    new-instance v1, Ljava/util/HashSet;

    .line 515
    .line 516
    invoke-direct {v1, v5}, Ljava/util/HashSet;-><init>(I)V

    .line 517
    .line 518
    .line 519
    new-instance v1, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 520
    .line 521
    invoke-direct {v1}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    .line 522
    .line 523
    .line 524
    new-instance v1, Ljava/util/concurrent/CopyOnWriteArrayList;

    .line 525
    .line 526
    invoke-direct {v1}, Ljava/util/concurrent/CopyOnWriteArrayList;-><init>()V

    .line 527
    .line 528
    .line 529
    sget-object v1, Lhr/h0;->e:Lhr/f0;

    .line 530
    .line 531
    sget-object v1, Lhr/x0;->h:Lhr/x0;

    .line 532
    .line 533
    sget-object v1, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;

    .line 534
    .line 535
    sget-object v1, Lhr/x0;->h:Lhr/x0;

    .line 536
    .line 537
    sget-object v1, Lt7/v;->a:Lt7/v;

    .line 538
    .line 539
    sget-object v1, Landroid/net/Uri;->EMPTY:Landroid/net/Uri;

    .line 540
    .line 541
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 542
    .line 543
    .line 544
    throw v3

    .line 545
    :cond_10
    new-instance v1, Lh8/l0;

    .line 546
    .line 547
    invoke-direct {v1, v4}, Lh8/l0;-><init>([Lh8/a;)V

    .line 548
    .line 549
    .line 550
    :cond_11
    iget-object v0, v14, Lt7/x;->e:Lt7/r;

    .line 551
    .line 552
    iget-wide v2, v0, Lt7/q;->a:J

    .line 553
    .line 554
    const-wide/high16 v6, -0x8000000000000000L

    .line 555
    .line 556
    cmp-long v2, v2, v6

    .line 557
    .line 558
    if-nez v2, :cond_12

    .line 559
    .line 560
    goto :goto_b

    .line 561
    :cond_12
    new-instance v2, Lh8/d;

    .line 562
    .line 563
    invoke-direct {v2, v1}, Lh8/d;-><init>(Lh8/a;)V

    .line 564
    .line 565
    .line 566
    iget-boolean v1, v2, Lh8/d;->d:Z

    .line 567
    .line 568
    xor-int/2addr v1, v5

    .line 569
    invoke-static {v1}, Lw7/a;->j(Z)V

    .line 570
    .line 571
    .line 572
    iget-wide v0, v0, Lt7/q;->a:J

    .line 573
    .line 574
    iget-boolean v3, v2, Lh8/d;->d:Z

    .line 575
    .line 576
    xor-int/2addr v3, v5

    .line 577
    invoke-static {v3}, Lw7/a;->j(Z)V

    .line 578
    .line 579
    .line 580
    iput-wide v0, v2, Lh8/d;->b:J

    .line 581
    .line 582
    iget-boolean v0, v2, Lh8/d;->d:Z

    .line 583
    .line 584
    xor-int/2addr v0, v5

    .line 585
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 586
    .line 587
    .line 588
    iput-boolean v5, v2, Lh8/d;->c:Z

    .line 589
    .line 590
    iget-boolean v0, v2, Lh8/d;->d:Z

    .line 591
    .line 592
    xor-int/2addr v0, v5

    .line 593
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 594
    .line 595
    .line 596
    iget-boolean v0, v2, Lh8/d;->d:Z

    .line 597
    .line 598
    xor-int/2addr v0, v5

    .line 599
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 600
    .line 601
    .line 602
    iget-boolean v0, v2, Lh8/d;->d:Z

    .line 603
    .line 604
    xor-int/2addr v0, v5

    .line 605
    invoke-static {v0}, Lw7/a;->j(Z)V

    .line 606
    .line 607
    .line 608
    iput-boolean v5, v2, Lh8/d;->d:Z

    .line 609
    .line 610
    new-instance v1, Lh8/g;

    .line 611
    .line 612
    invoke-direct {v1, v2}, Lh8/g;-><init>(Lh8/d;)V

    .line 613
    .line 614
    .line 615
    :goto_b
    iget-object v0, v14, Lt7/x;->b:Lt7/u;

    .line 616
    .line 617
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 618
    .line 619
    .line 620
    iget-object v0, v14, Lt7/x;->b:Lt7/u;

    .line 621
    .line 622
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 623
    .line 624
    .line 625
    return-object v1

    .line 626
    :catch_0
    move-exception v0

    .line 627
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 628
    .line 629
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/Throwable;)V

    .line 630
    .line 631
    .line 632
    throw v1

    .line 633
    :cond_13
    iget-object v0, v1, Lt7/x;->b:Lt7/u;

    .line 634
    .line 635
    iget-wide v0, v0, Lt7/u;->e:J

    .line 636
    .line 637
    sget-object v0, Lw7/w;->a:Ljava/lang/String;

    .line 638
    .line 639
    throw v3
.end method

.method public final c(Z)V
    .locals 1

    .line 1
    iput-boolean p1, p0, Lh8/p;->i:Z

    .line 2
    .line 3
    iget-object p0, p0, Lh8/p;->a:Lh8/o;

    .line 4
    .line 5
    iput-boolean p1, p0, Lh8/o;->a:Z

    .line 6
    .line 7
    iget-object v0, p0, Lh8/o;->b:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v0, Lo8/m;

    .line 10
    .line 11
    monitor-enter v0

    .line 12
    :try_start_0
    iput-boolean p1, v0, Lo8/m;->e:Z
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    .line 14
    monitor-exit v0

    .line 15
    iget-object p0, p0, Lh8/o;->d:Ljava/lang/Object;

    .line 16
    .line 17
    check-cast p0, Ljava/util/HashMap;

    .line 18
    .line 19
    invoke-virtual {p0}, Ljava/util/HashMap;->values()Ljava/util/Collection;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    invoke-interface {p0}, Ljava/util/Collection;->iterator()Ljava/util/Iterator;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    :goto_0
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 28
    .line 29
    .line 30
    move-result v0

    .line 31
    if-eqz v0, :cond_0

    .line 32
    .line 33
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    check-cast v0, Lh8/a0;

    .line 38
    .line 39
    invoke-interface {v0, p1}, Lh8/a0;->c(Z)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :cond_0
    return-void

    .line 44
    :catchall_0
    move-exception p0

    .line 45
    :try_start_1
    monitor-exit v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 46
    throw p0
.end method

.method public final d()V
    .locals 0

    .line 1
    iget-object p0, p0, Lh8/p;->a:Lh8/o;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lh8/o;->b:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast p0, Lo8/m;

    .line 9
    .line 10
    monitor-enter p0

    .line 11
    monitor-exit p0

    .line 12
    return-void
.end method
