.class public final Lim/o;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ldm/g;


# instance fields
.field public final a:Ljava/lang/String;

.field public final b:Lmm/n;

.field public final c:Llx0/i;

.field public final d:Llx0/q;

.field public final e:Llx0/i;

.field public final f:Lim/e;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lmm/n;Llx0/q;Llx0/q;Llx0/q;Lim/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lim/o;->a:Ljava/lang/String;

    .line 5
    .line 6
    iput-object p2, p0, Lim/o;->b:Lmm/n;

    .line 7
    .line 8
    iput-object p3, p0, Lim/o;->c:Llx0/i;

    .line 9
    .line 10
    iput-object p4, p0, Lim/o;->d:Llx0/q;

    .line 11
    .line 12
    iput-object p5, p0, Lim/o;->e:Llx0/i;

    .line 13
    .line 14
    iput-object p6, p0, Lim/o;->f:Lim/e;

    .line 15
    .line 16
    return-void
.end method

.method public static final b(Lim/o;Lim/s;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lim/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lim/m;

    .line 7
    .line 8
    iget v1, v0, Lim/m;->g:I

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
    iput v1, v0, Lim/m;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lim/m;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lim/m;-><init>(Lim/o;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lim/m;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lim/m;->g:I

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
    iget-object p1, v0, Lim/m;->d:Lu01/f;

    .line 37
    .line 38
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    new-instance p2, Lu01/f;

    .line 54
    .line 55
    invoke-direct {p2}, Ljava/lang/Object;-><init>()V

    .line 56
    .line 57
    .line 58
    iput-object p2, v0, Lim/m;->d:Lu01/f;

    .line 59
    .line 60
    iput v3, v0, Lim/m;->g:I

    .line 61
    .line 62
    iget-object p1, p1, Lim/s;->d:Lu01/h;

    .line 63
    .line 64
    invoke-interface {p1, p2}, Lu01/h;->L(Lu01/g;)J

    .line 65
    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    if-ne p1, v1, :cond_3

    .line 70
    .line 71
    return-object v1

    .line 72
    :cond_3
    move-object p1, p2

    .line 73
    :goto_1
    invoke-virtual {p0}, Lim/o;->e()Lu01/k;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    new-instance p2, Lbm/s;

    .line 78
    .line 79
    const/4 v0, 0x0

    .line 80
    invoke-direct {p2, p1, p0, v0}, Lbm/s;-><init>(Lu01/h;Lu01/k;Ljp/ua;)V

    .line 81
    .line 82
    .line 83
    return-object p2
.end method

.method public static final c(Lim/o;Lcm/f;Lim/r;Lim/r;Lrx0/c;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    move-object/from16 v4, p4

    .line 10
    .line 11
    instance-of v5, v4, Lim/n;

    .line 12
    .line 13
    if-eqz v5, :cond_0

    .line 14
    .line 15
    move-object v5, v4

    .line 16
    check-cast v5, Lim/n;

    .line 17
    .line 18
    iget v6, v5, Lim/n;->j:I

    .line 19
    .line 20
    const/high16 v7, -0x80000000

    .line 21
    .line 22
    and-int v8, v6, v7

    .line 23
    .line 24
    if-eqz v8, :cond_0

    .line 25
    .line 26
    sub-int/2addr v6, v7

    .line 27
    iput v6, v5, Lim/n;->j:I

    .line 28
    .line 29
    goto :goto_0

    .line 30
    :cond_0
    new-instance v5, Lim/n;

    .line 31
    .line 32
    invoke-direct {v5, v1, v4}, Lim/n;-><init>(Lim/o;Lrx0/c;)V

    .line 33
    .line 34
    .line 35
    :goto_0
    iget-object v4, v5, Lim/n;->h:Ljava/lang/Object;

    .line 36
    .line 37
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 38
    .line 39
    iget v7, v5, Lim/n;->j:I

    .line 40
    .line 41
    const/4 v8, 0x2

    .line 42
    const/4 v9, 0x0

    .line 43
    const/4 v10, 0x1

    .line 44
    const/4 v11, 0x0

    .line 45
    if-eqz v7, :cond_3

    .line 46
    .line 47
    if-eq v7, v10, :cond_2

    .line 48
    .line 49
    if-ne v7, v8, :cond_1

    .line 50
    .line 51
    iget-object v1, v5, Lim/n;->g:Lbu/c;

    .line 52
    .line 53
    iget-object v2, v5, Lim/n;->f:Lim/r;

    .line 54
    .line 55
    iget-object v3, v5, Lim/n;->e:Lim/r;

    .line 56
    .line 57
    :try_start_0
    invoke-static {v4}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 58
    .line 59
    .line 60
    goto/16 :goto_e

    .line 61
    .line 62
    :catch_0
    move-exception v0

    .line 63
    goto/16 :goto_10

    .line 64
    .line 65
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 66
    .line 67
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 68
    .line 69
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw v0

    .line 73
    :cond_2
    iget-object v0, v5, Lim/n;->e:Lim/r;

    .line 74
    .line 75
    iget-object v2, v5, Lim/n;->d:Lcm/f;

    .line 76
    .line 77
    invoke-static {v4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    move-object v3, v0

    .line 81
    move-object v0, v2

    .line 82
    move-object/from16 p4, v11

    .line 83
    .line 84
    goto/16 :goto_4

    .line 85
    .line 86
    :cond_3
    invoke-static {v4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    iget-object v4, v1, Lim/o;->b:Lmm/n;

    .line 90
    .line 91
    iget-object v4, v4, Lmm/n;->h:Lmm/b;

    .line 92
    .line 93
    iget-boolean v4, v4, Lmm/b;->e:Z

    .line 94
    .line 95
    if-nez v4, :cond_5

    .line 96
    .line 97
    if-eqz v0, :cond_4

    .line 98
    .line 99
    :try_start_1
    invoke-static {v0}, Lp3/m;->x(Ljava/lang/AutoCloseable;)V
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 100
    .line 101
    .line 102
    :catch_1
    return-object v11

    .line 103
    :catch_2
    move-exception v0

    .line 104
    throw v0

    .line 105
    :cond_4
    move-object/from16 p4, v11

    .line 106
    .line 107
    goto/16 :goto_6

    .line 108
    .line 109
    :cond_5
    iget-object v4, v1, Lim/o;->e:Llx0/i;

    .line 110
    .line 111
    invoke-interface {v4}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object v4

    .line 115
    check-cast v4, Lim/c;

    .line 116
    .line 117
    iput-object v0, v5, Lim/n;->d:Lcm/f;

    .line 118
    .line 119
    iput-object v3, v5, Lim/n;->e:Lim/r;

    .line 120
    .line 121
    iput v10, v5, Lim/n;->j:I

    .line 122
    .line 123
    check-cast v4, Ljm/a;

    .line 124
    .line 125
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 126
    .line 127
    .line 128
    iget v4, v3, Lim/r;->a:I

    .line 129
    .line 130
    const/16 v7, 0x130

    .line 131
    .line 132
    if-ne v4, v7, :cond_8

    .line 133
    .line 134
    if-eqz v2, :cond_8

    .line 135
    .line 136
    iget-object v2, v2, Lim/r;->d:Lim/p;

    .line 137
    .line 138
    iget-object v4, v3, Lim/r;->d:Lim/p;

    .line 139
    .line 140
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 141
    .line 142
    .line 143
    iget-object v2, v2, Lim/p;->a:Ljava/util/Map;

    .line 144
    .line 145
    new-instance v7, Ljava/util/LinkedHashMap;

    .line 146
    .line 147
    invoke-direct {v7}, Ljava/util/LinkedHashMap;-><init>()V

    .line 148
    .line 149
    .line 150
    invoke-interface {v2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    check-cast v2, Ljava/lang/Iterable;

    .line 155
    .line 156
    invoke-interface {v2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 157
    .line 158
    .line 159
    move-result-object v2

    .line 160
    :goto_1
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 161
    .line 162
    .line 163
    move-result v12

    .line 164
    if-eqz v12, :cond_6

    .line 165
    .line 166
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v12

    .line 170
    check-cast v12, Ljava/util/Map$Entry;

    .line 171
    .line 172
    invoke-interface {v12}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 173
    .line 174
    .line 175
    move-result-object v13

    .line 176
    invoke-interface {v12}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object v12

    .line 180
    check-cast v12, Ljava/util/Collection;

    .line 181
    .line 182
    invoke-static {v12}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 183
    .line 184
    .line 185
    move-result-object v12

    .line 186
    invoke-interface {v7, v13, v12}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    goto :goto_1

    .line 190
    :cond_6
    iget-object v2, v4, Lim/p;->a:Ljava/util/Map;

    .line 191
    .line 192
    invoke-interface {v2}, Ljava/util/Map;->entrySet()Ljava/util/Set;

    .line 193
    .line 194
    .line 195
    move-result-object v2

    .line 196
    invoke-interface {v2}, Ljava/util/Set;->iterator()Ljava/util/Iterator;

    .line 197
    .line 198
    .line 199
    move-result-object v2

    .line 200
    :goto_2
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 201
    .line 202
    .line 203
    move-result v4

    .line 204
    if-eqz v4, :cond_7

    .line 205
    .line 206
    invoke-interface {v2}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v4

    .line 210
    check-cast v4, Ljava/util/Map$Entry;

    .line 211
    .line 212
    invoke-interface {v4}, Ljava/util/Map$Entry;->getKey()Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v12

    .line 216
    check-cast v12, Ljava/lang/String;

    .line 217
    .line 218
    invoke-interface {v4}, Ljava/util/Map$Entry;->getValue()Ljava/lang/Object;

    .line 219
    .line 220
    .line 221
    move-result-object v4

    .line 222
    check-cast v4, Ljava/util/List;

    .line 223
    .line 224
    sget-object v13, Ljava/util/Locale;->ROOT:Ljava/util/Locale;

    .line 225
    .line 226
    invoke-virtual {v12, v13}, Ljava/lang/String;->toLowerCase(Ljava/util/Locale;)Ljava/lang/String;

    .line 227
    .line 228
    .line 229
    move-result-object v12

    .line 230
    const-string v13, "toLowerCase(...)"

    .line 231
    .line 232
    invoke-static {v12, v13}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 233
    .line 234
    .line 235
    check-cast v4, Ljava/util/Collection;

    .line 236
    .line 237
    invoke-static {v4}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 238
    .line 239
    .line 240
    move-result-object v4

    .line 241
    invoke-interface {v7, v12, v4}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    goto :goto_2

    .line 245
    :cond_7
    new-instance v2, Lim/p;

    .line 246
    .line 247
    invoke-static {v7}, Lmx0/x;->u(Ljava/util/Map;)Ljava/util/Map;

    .line 248
    .line 249
    .line 250
    move-result-object v4

    .line 251
    invoke-direct {v2, v4}, Lim/p;-><init>(Ljava/util/Map;)V

    .line 252
    .line 253
    .line 254
    new-instance v4, Lim/b;

    .line 255
    .line 256
    iget v14, v3, Lim/r;->a:I

    .line 257
    .line 258
    iget-wide v12, v3, Lim/r;->b:J

    .line 259
    .line 260
    move-object/from16 p4, v11

    .line 261
    .line 262
    move-wide v15, v12

    .line 263
    iget-wide v11, v3, Lim/r;->c:J

    .line 264
    .line 265
    iget-object v7, v3, Lim/r;->f:Ljava/lang/Object;

    .line 266
    .line 267
    new-instance v13, Lim/r;

    .line 268
    .line 269
    const/16 v20, 0x0

    .line 270
    .line 271
    move-object/from16 v19, v2

    .line 272
    .line 273
    move-object/from16 v21, v7

    .line 274
    .line 275
    move-wide/from16 v17, v11

    .line 276
    .line 277
    invoke-direct/range {v13 .. v21}, Lim/r;-><init>(IJJLim/p;Lim/s;Ljava/lang/Object;)V

    .line 278
    .line 279
    .line 280
    invoke-direct {v4, v13}, Lim/b;-><init>(Lim/r;)V

    .line 281
    .line 282
    .line 283
    goto :goto_3

    .line 284
    :cond_8
    move-object/from16 p4, v11

    .line 285
    .line 286
    new-instance v2, Lim/b;

    .line 287
    .line 288
    invoke-direct {v2, v3}, Lim/b;-><init>(Lim/r;)V

    .line 289
    .line 290
    .line 291
    move-object v4, v2

    .line 292
    :goto_3
    if-ne v4, v6, :cond_9

    .line 293
    .line 294
    goto/16 :goto_f

    .line 295
    .line 296
    :cond_9
    :goto_4
    check-cast v4, Lim/b;

    .line 297
    .line 298
    iget-object v2, v4, Lim/b;->a:Lim/r;

    .line 299
    .line 300
    if-nez v2, :cond_a

    .line 301
    .line 302
    goto :goto_6

    .line 303
    :cond_a
    const/16 v4, 0xa

    .line 304
    .line 305
    if-eqz v0, :cond_b

    .line 306
    .line 307
    iget-object v0, v0, Lcm/f;->d:Lcm/b;

    .line 308
    .line 309
    iget-object v7, v0, Lcm/b;->f:Lcm/d;

    .line 310
    .line 311
    iget-object v11, v7, Lcm/d;->k:Ljava/lang/Object;

    .line 312
    .line 313
    monitor-enter v11

    .line 314
    :try_start_2
    invoke-virtual {v0}, Lcm/b;->close()V

    .line 315
    .line 316
    .line 317
    iget-object v0, v0, Lcm/b;->d:Lcm/a;

    .line 318
    .line 319
    iget-object v0, v0, Lcm/a;->a:Ljava/lang/String;

    .line 320
    .line 321
    invoke-virtual {v7, v0}, Lcm/d;->b(Ljava/lang/String;)La8/b;

    .line 322
    .line 323
    .line 324
    move-result-object v0
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 325
    monitor-exit v11

    .line 326
    if-eqz v0, :cond_d

    .line 327
    .line 328
    new-instance v7, Lbu/c;

    .line 329
    .line 330
    invoke-direct {v7, v0, v4}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 331
    .line 332
    .line 333
    goto :goto_5

    .line 334
    :catchall_0
    move-exception v0

    .line 335
    monitor-exit v11

    .line 336
    throw v0

    .line 337
    :cond_b
    iget-object v0, v1, Lim/o;->d:Llx0/q;

    .line 338
    .line 339
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 340
    .line 341
    .line 342
    move-result-object v0

    .line 343
    check-cast v0, Lcm/g;

    .line 344
    .line 345
    if-eqz v0, :cond_d

    .line 346
    .line 347
    iget-object v7, v1, Lim/o;->b:Lmm/n;

    .line 348
    .line 349
    iget-object v7, v7, Lmm/n;->e:Ljava/lang/String;

    .line 350
    .line 351
    if-nez v7, :cond_c

    .line 352
    .line 353
    iget-object v7, v1, Lim/o;->a:Ljava/lang/String;

    .line 354
    .line 355
    :cond_c
    iget-object v0, v0, Lcm/g;->b:Lcm/d;

    .line 356
    .line 357
    sget-object v11, Lu01/i;->g:Lu01/i;

    .line 358
    .line 359
    invoke-static {v7}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 360
    .line 361
    .line 362
    move-result-object v7

    .line 363
    const-string v11, "SHA-256"

    .line 364
    .line 365
    invoke-virtual {v7, v11}, Lu01/i;->c(Ljava/lang/String;)Lu01/i;

    .line 366
    .line 367
    .line 368
    move-result-object v7

    .line 369
    invoke-virtual {v7}, Lu01/i;->e()Ljava/lang/String;

    .line 370
    .line 371
    .line 372
    move-result-object v7

    .line 373
    invoke-virtual {v0, v7}, Lcm/d;->b(Ljava/lang/String;)La8/b;

    .line 374
    .line 375
    .line 376
    move-result-object v0

    .line 377
    if-eqz v0, :cond_d

    .line 378
    .line 379
    new-instance v7, Lbu/c;

    .line 380
    .line 381
    invoke-direct {v7, v0, v4}, Lbu/c;-><init>(Ljava/lang/Object;I)V

    .line 382
    .line 383
    .line 384
    goto :goto_5

    .line 385
    :cond_d
    move-object/from16 v7, p4

    .line 386
    .line 387
    :goto_5
    if-nez v7, :cond_e

    .line 388
    .line 389
    :goto_6
    return-object p4

    .line 390
    :cond_e
    :try_start_3
    invoke-virtual {v1}, Lim/o;->e()Lu01/k;

    .line 391
    .line 392
    .line 393
    move-result-object v0

    .line 394
    iget-object v4, v7, Lbu/c;->e:Ljava/lang/Object;

    .line 395
    .line 396
    check-cast v4, La8/b;

    .line 397
    .line 398
    invoke-virtual {v4, v9}, La8/b;->h(I)Lu01/y;

    .line 399
    .line 400
    .line 401
    move-result-object v4

    .line 402
    invoke-virtual {v0, v4, v9}, Lu01/k;->E(Lu01/y;Z)Lu01/f0;

    .line 403
    .line 404
    .line 405
    move-result-object v0

    .line 406
    invoke-static {v0}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 407
    .line 408
    .line 409
    move-result-object v4
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_3

    .line 410
    :try_start_4
    invoke-static {v2, v4}, Llp/na;->f(Lim/r;Lu01/a0;)V
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_2

    .line 411
    .line 412
    .line 413
    :try_start_5
    invoke-virtual {v4}, Lu01/a0;->close()V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_1

    .line 414
    .line 415
    .line 416
    move-object/from16 v0, p4

    .line 417
    .line 418
    goto :goto_8

    .line 419
    :catchall_1
    move-exception v0

    .line 420
    goto :goto_8

    .line 421
    :catchall_2
    move-exception v0

    .line 422
    move-object v11, v0

    .line 423
    :try_start_6
    invoke-virtual {v4}, Lu01/a0;->close()V
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_3

    .line 424
    .line 425
    .line 426
    goto :goto_7

    .line 427
    :catchall_3
    move-exception v0

    .line 428
    :try_start_7
    invoke-static {v11, v0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 429
    .line 430
    .line 431
    :goto_7
    move-object v0, v11

    .line 432
    :goto_8
    if-nez v0, :cond_13

    .line 433
    .line 434
    iget-object v0, v2, Lim/r;->e:Lim/s;

    .line 435
    .line 436
    if-eqz v0, :cond_10

    .line 437
    .line 438
    invoke-virtual {v1}, Lim/o;->e()Lu01/k;

    .line 439
    .line 440
    .line 441
    move-result-object v1

    .line 442
    iget-object v4, v7, Lbu/c;->e:Ljava/lang/Object;

    .line 443
    .line 444
    check-cast v4, La8/b;

    .line 445
    .line 446
    invoke-virtual {v4, v10}, La8/b;->h(I)Lu01/y;

    .line 447
    .line 448
    .line 449
    move-result-object v4

    .line 450
    move-object/from16 v11, p4

    .line 451
    .line 452
    iput-object v11, v5, Lim/n;->d:Lcm/f;

    .line 453
    .line 454
    iput-object v3, v5, Lim/n;->e:Lim/r;

    .line 455
    .line 456
    iput-object v2, v5, Lim/n;->f:Lim/r;

    .line 457
    .line 458
    iput-object v7, v5, Lim/n;->g:Lbu/c;

    .line 459
    .line 460
    iput v8, v5, Lim/n;->j:I

    .line 461
    .line 462
    iget-object v0, v0, Lim/s;->d:Lu01/h;

    .line 463
    .line 464
    invoke-virtual {v1, v4, v9}, Lu01/k;->E(Lu01/y;Z)Lu01/f0;

    .line 465
    .line 466
    .line 467
    move-result-object v1

    .line 468
    invoke-static {v1}, Lu01/b;->b(Lu01/f0;)Lu01/a0;

    .line 469
    .line 470
    .line 471
    move-result-object v1
    :try_end_7
    .catch Ljava/lang/Exception; {:try_start_7 .. :try_end_7} :catch_3

    .line 472
    :try_start_8
    invoke-interface {v0, v1}, Lu01/h;->L(Lu01/g;)J

    .line 473
    .line 474
    .line 475
    move-result-wide v4

    .line 476
    new-instance v0, Ljava/lang/Long;

    .line 477
    .line 478
    invoke-direct {v0, v4, v5}, Ljava/lang/Long;-><init>(J)V
    :try_end_8
    .catchall {:try_start_8 .. :try_end_8} :catchall_5

    .line 479
    .line 480
    .line 481
    :try_start_9
    invoke-virtual {v1}, Lu01/a0;->close()V
    :try_end_9
    .catchall {:try_start_9 .. :try_end_9} :catchall_4

    .line 482
    .line 483
    .line 484
    move-object v0, v11

    .line 485
    goto :goto_c

    .line 486
    :catchall_4
    move-exception v0

    .line 487
    goto :goto_c

    .line 488
    :goto_9
    move-object v4, v0

    .line 489
    goto :goto_a

    .line 490
    :catchall_5
    move-exception v0

    .line 491
    goto :goto_9

    .line 492
    :goto_a
    :try_start_a
    invoke-virtual {v1}, Lu01/a0;->close()V
    :try_end_a
    .catchall {:try_start_a .. :try_end_a} :catchall_6

    .line 493
    .line 494
    .line 495
    goto :goto_b

    .line 496
    :catchall_6
    move-exception v0

    .line 497
    :try_start_b
    invoke-static {v4, v0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 498
    .line 499
    .line 500
    :goto_b
    move-object v0, v4

    .line 501
    :goto_c
    if-nez v0, :cond_f

    .line 502
    .line 503
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 504
    .line 505
    if-ne v0, v6, :cond_11

    .line 506
    .line 507
    goto :goto_f

    .line 508
    :cond_f
    throw v0
    :try_end_b
    .catch Ljava/lang/Exception; {:try_start_b .. :try_end_b} :catch_3

    .line 509
    :goto_d
    move-object v1, v7

    .line 510
    goto :goto_10

    .line 511
    :catch_3
    move-exception v0

    .line 512
    goto :goto_d

    .line 513
    :cond_10
    move-object/from16 v11, p4

    .line 514
    .line 515
    :cond_11
    move-object v1, v7

    .line 516
    :goto_e
    :try_start_c
    iget-object v0, v1, Lbu/c;->e:Ljava/lang/Object;

    .line 517
    .line 518
    check-cast v0, La8/b;

    .line 519
    .line 520
    iget-object v4, v0, La8/b;->h:Ljava/lang/Object;

    .line 521
    .line 522
    check-cast v4, Lcm/d;

    .line 523
    .line 524
    iget-object v5, v4, Lcm/d;->k:Ljava/lang/Object;

    .line 525
    .line 526
    monitor-enter v5
    :try_end_c
    .catch Ljava/lang/Exception; {:try_start_c .. :try_end_c} :catch_0

    .line 527
    :try_start_d
    invoke-virtual {v0, v10}, La8/b;->e(Z)V

    .line 528
    .line 529
    .line 530
    iget-object v0, v0, La8/b;->f:Ljava/lang/Object;

    .line 531
    .line 532
    check-cast v0, Lcm/a;

    .line 533
    .line 534
    iget-object v0, v0, Lcm/a;->a:Ljava/lang/String;

    .line 535
    .line 536
    invoke-virtual {v4, v0}, Lcm/d;->d(Ljava/lang/String;)Lcm/b;

    .line 537
    .line 538
    .line 539
    move-result-object v0
    :try_end_d
    .catchall {:try_start_d .. :try_end_d} :catchall_7

    .line 540
    :try_start_e
    monitor-exit v5

    .line 541
    if-eqz v0, :cond_12

    .line 542
    .line 543
    new-instance v4, Lcm/f;

    .line 544
    .line 545
    invoke-direct {v4, v0}, Lcm/f;-><init>(Lcm/b;)V

    .line 546
    .line 547
    .line 548
    move-object v6, v4

    .line 549
    goto :goto_f

    .line 550
    :cond_12
    move-object v6, v11

    .line 551
    :goto_f
    return-object v6

    .line 552
    :catchall_7
    move-exception v0

    .line 553
    monitor-exit v5

    .line 554
    throw v0
    :try_end_e
    .catch Ljava/lang/Exception; {:try_start_e .. :try_end_e} :catch_0

    .line 555
    :cond_13
    :try_start_f
    throw v0
    :try_end_f
    .catch Ljava/lang/Exception; {:try_start_f .. :try_end_f} :catch_3

    .line 556
    :goto_10
    :try_start_10
    iget-object v1, v1, Lbu/c;->e:Ljava/lang/Object;

    .line 557
    .line 558
    check-cast v1, La8/b;

    .line 559
    .line 560
    invoke-virtual {v1, v9}, La8/b;->e(Z)V
    :try_end_10
    .catch Ljava/lang/Exception; {:try_start_10 .. :try_end_10} :catch_4

    .line 561
    .line 562
    .line 563
    :catch_4
    iget-object v1, v3, Lim/r;->e:Lim/s;

    .line 564
    .line 565
    if-eqz v1, :cond_14

    .line 566
    .line 567
    :try_start_11
    invoke-static {v1}, Lp3/m;->x(Ljava/lang/AutoCloseable;)V
    :try_end_11
    .catch Ljava/lang/RuntimeException; {:try_start_11 .. :try_end_11} :catch_5
    .catch Ljava/lang/Exception; {:try_start_11 .. :try_end_11} :catch_6

    .line 568
    .line 569
    .line 570
    goto :goto_11

    .line 571
    :catch_5
    move-exception v0

    .line 572
    throw v0

    .line 573
    :catch_6
    :cond_14
    :goto_11
    iget-object v1, v2, Lim/r;->e:Lim/s;

    .line 574
    .line 575
    if-eqz v1, :cond_15

    .line 576
    .line 577
    :try_start_12
    invoke-static {v1}, Lp3/m;->x(Ljava/lang/AutoCloseable;)V
    :try_end_12
    .catch Ljava/lang/RuntimeException; {:try_start_12 .. :try_end_12} :catch_7
    .catch Ljava/lang/Exception; {:try_start_12 .. :try_end_12} :catch_8

    .line 578
    .line 579
    .line 580
    goto :goto_12

    .line 581
    :catch_7
    move-exception v0

    .line 582
    throw v0

    .line 583
    :catch_8
    :cond_15
    :goto_12
    throw v0
.end method

.method public static f(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 2

    .line 1
    if-eqz p1, :cond_0

    .line 2
    .line 3
    const-string v0, "text/plain"

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-static {p1, v0, v1}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    :cond_0
    invoke-static {p0}, Lkp/j8;->b(Ljava/lang/String;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    if-eqz p0, :cond_1

    .line 17
    .line 18
    return-object p0

    .line 19
    :cond_1
    if-eqz p1, :cond_2

    .line 20
    .line 21
    const/16 p0, 0x3b

    .line 22
    .line 23
    invoke-static {p1, p0}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :cond_2
    const/4 p0, 0x0

    .line 29
    return-object p0
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 15

    .line 1
    move-object/from16 v0, p1

    .line 2
    .line 3
    instance-of v1, v0, Lim/l;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Lim/l;

    .line 9
    .line 10
    iget v3, v1, Lim/l;->h:I

    .line 11
    .line 12
    const/high16 v4, -0x80000000

    .line 13
    .line 14
    and-int v5, v3, v4

    .line 15
    .line 16
    if-eqz v5, :cond_0

    .line 17
    .line 18
    sub-int/2addr v3, v4

    .line 19
    iput v3, v1, Lim/l;->h:I

    .line 20
    .line 21
    :goto_0
    move-object v7, v1

    .line 22
    goto :goto_1

    .line 23
    :cond_0
    new-instance v1, Lim/l;

    .line 24
    .line 25
    check-cast v0, Lrx0/c;

    .line 26
    .line 27
    invoke-direct {v1, p0, v0}, Lim/l;-><init>(Lim/o;Lrx0/c;)V

    .line 28
    .line 29
    .line 30
    goto :goto_0

    .line 31
    :goto_1
    iget-object v0, v7, Lim/l;->f:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v1, v7, Lim/l;->h:I

    .line 36
    .line 37
    iget-object v3, p0, Lim/o;->a:Ljava/lang/String;

    .line 38
    .line 39
    const/4 v9, 0x3

    .line 40
    const/4 v10, 0x2

    .line 41
    const/4 v4, 0x1

    .line 42
    const/4 v11, 0x0

    .line 43
    if-eqz v1, :cond_4

    .line 44
    .line 45
    if-eq v1, v4, :cond_3

    .line 46
    .line 47
    if-eq v1, v10, :cond_2

    .line 48
    .line 49
    if-ne v1, v9, :cond_1

    .line 50
    .line 51
    iget-object v1, v7, Lim/l;->e:Lkotlin/jvm/internal/f0;

    .line 52
    .line 53
    check-cast v1, Lim/a;

    .line 54
    .line 55
    iget-object v1, v7, Lim/l;->d:Lkotlin/jvm/internal/f0;

    .line 56
    .line 57
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 58
    .line 59
    .line 60
    goto/16 :goto_8

    .line 61
    .line 62
    :catch_0
    move-exception v0

    .line 63
    goto/16 :goto_9

    .line 64
    .line 65
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 66
    .line 67
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 68
    .line 69
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw v0

    .line 73
    :cond_2
    iget-object v1, v7, Lim/l;->e:Lkotlin/jvm/internal/f0;

    .line 74
    .line 75
    check-cast v1, Lim/a;

    .line 76
    .line 77
    iget-object v1, v7, Lim/l;->d:Lkotlin/jvm/internal/f0;

    .line 78
    .line 79
    :try_start_1
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_0

    .line 80
    .line 81
    .line 82
    goto/16 :goto_6

    .line 83
    .line 84
    :cond_3
    iget-object v1, v7, Lim/l;->e:Lkotlin/jvm/internal/f0;

    .line 85
    .line 86
    iget-object v4, v7, Lim/l;->d:Lkotlin/jvm/internal/f0;

    .line 87
    .line 88
    :try_start_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_1

    .line 89
    .line 90
    .line 91
    move-object v14, v4

    .line 92
    move-object v4, v1

    .line 93
    move-object v1, v14

    .line 94
    goto/16 :goto_4

    .line 95
    .line 96
    :catch_1
    move-exception v0

    .line 97
    move-object v1, v4

    .line 98
    goto/16 :goto_9

    .line 99
    .line 100
    :cond_4
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    new-instance v1, Lkotlin/jvm/internal/f0;

    .line 104
    .line 105
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 106
    .line 107
    .line 108
    iget-object v0, p0, Lim/o;->b:Lmm/n;

    .line 109
    .line 110
    iget-object v5, v0, Lmm/n;->h:Lmm/b;

    .line 111
    .line 112
    iget-boolean v5, v5, Lmm/b;->d:Z

    .line 113
    .line 114
    if-eqz v5, :cond_6

    .line 115
    .line 116
    iget-object v5, p0, Lim/o;->d:Llx0/q;

    .line 117
    .line 118
    invoke-virtual {v5}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v5

    .line 122
    check-cast v5, Lcm/g;

    .line 123
    .line 124
    if-eqz v5, :cond_6

    .line 125
    .line 126
    iget-object v0, v0, Lmm/n;->e:Ljava/lang/String;

    .line 127
    .line 128
    if-nez v0, :cond_5

    .line 129
    .line 130
    move-object v0, v3

    .line 131
    :cond_5
    iget-object v5, v5, Lcm/g;->b:Lcm/d;

    .line 132
    .line 133
    sget-object v6, Lu01/i;->g:Lu01/i;

    .line 134
    .line 135
    invoke-static {v0}, Lpy/a;->m(Ljava/lang/String;)Lu01/i;

    .line 136
    .line 137
    .line 138
    move-result-object v0

    .line 139
    const-string v6, "SHA-256"

    .line 140
    .line 141
    invoke-virtual {v0, v6}, Lu01/i;->c(Ljava/lang/String;)Lu01/i;

    .line 142
    .line 143
    .line 144
    move-result-object v0

    .line 145
    invoke-virtual {v0}, Lu01/i;->e()Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v0

    .line 149
    invoke-virtual {v5, v0}, Lcm/d;->d(Ljava/lang/String;)Lcm/b;

    .line 150
    .line 151
    .line 152
    move-result-object v0

    .line 153
    if-eqz v0, :cond_6

    .line 154
    .line 155
    new-instance v5, Lcm/f;

    .line 156
    .line 157
    invoke-direct {v5, v0}, Lcm/f;-><init>(Lcm/b;)V

    .line 158
    .line 159
    .line 160
    goto :goto_2

    .line 161
    :cond_6
    move-object v5, v11

    .line 162
    :goto_2
    iput-object v5, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 163
    .line 164
    :try_start_3
    new-instance v0, Lkotlin/jvm/internal/f0;

    .line 165
    .line 166
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 167
    .line 168
    .line 169
    if-eqz v5, :cond_c

    .line 170
    .line 171
    invoke-virtual {p0}, Lim/o;->e()Lu01/k;

    .line 172
    .line 173
    .line 174
    move-result-object v5

    .line 175
    iget-object v6, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 176
    .line 177
    check-cast v6, Lcm/f;

    .line 178
    .line 179
    iget-object v6, v6, Lcm/f;->d:Lcm/b;

    .line 180
    .line 181
    iget-boolean v12, v6, Lcm/b;->e:Z

    .line 182
    .line 183
    if-nez v12, :cond_b

    .line 184
    .line 185
    iget-object v6, v6, Lcm/b;->d:Lcm/a;

    .line 186
    .line 187
    iget-object v6, v6, Lcm/a;->c:Ljava/util/ArrayList;

    .line 188
    .line 189
    const/4 v12, 0x0

    .line 190
    invoke-virtual {v6, v12}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object v6

    .line 194
    check-cast v6, Lu01/y;

    .line 195
    .line 196
    invoke-virtual {v5, v6}, Lu01/k;->l(Lu01/y;)Li5/f;

    .line 197
    .line 198
    .line 199
    move-result-object v5

    .line 200
    iget-object v5, v5, Li5/f;->e:Ljava/lang/Object;

    .line 201
    .line 202
    check-cast v5, Ljava/lang/Long;

    .line 203
    .line 204
    if-nez v5, :cond_7

    .line 205
    .line 206
    goto :goto_3

    .line 207
    :cond_7
    invoke-virtual {v5}, Ljava/lang/Long;->longValue()J

    .line 208
    .line 209
    .line 210
    move-result-wide v5

    .line 211
    const-wide/16 v12, 0x0

    .line 212
    .line 213
    cmp-long v5, v5, v12

    .line 214
    .line 215
    if-nez v5, :cond_8

    .line 216
    .line 217
    new-instance v0, Ldm/i;

    .line 218
    .line 219
    iget-object v4, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 220
    .line 221
    check-cast v4, Lcm/f;

    .line 222
    .line 223
    invoke-virtual {p0, v4}, Lim/o;->h(Lcm/f;)Lbm/p;

    .line 224
    .line 225
    .line 226
    move-result-object v2

    .line 227
    invoke-static {v3, v11}, Lim/o;->f(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object v3

    .line 231
    sget-object v4, Lbm/h;->f:Lbm/h;

    .line 232
    .line 233
    invoke-direct {v0, v2, v3, v4}, Ldm/i;-><init>(Lbm/q;Ljava/lang/String;Lbm/h;)V

    .line 234
    .line 235
    .line 236
    return-object v0

    .line 237
    :cond_8
    :goto_3
    iget-object v5, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v5, Lcm/f;

    .line 240
    .line 241
    invoke-virtual {p0, v5}, Lim/o;->i(Lcm/f;)Lim/r;

    .line 242
    .line 243
    .line 244
    move-result-object v5

    .line 245
    iput-object v5, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 246
    .line 247
    if-eqz v5, :cond_c

    .line 248
    .line 249
    iget-object v5, p0, Lim/o;->e:Llx0/i;

    .line 250
    .line 251
    invoke-interface {v5}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 252
    .line 253
    .line 254
    move-result-object v5

    .line 255
    check-cast v5, Lim/c;

    .line 256
    .line 257
    iget-object v6, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 258
    .line 259
    check-cast v6, Lim/r;

    .line 260
    .line 261
    invoke-virtual {p0}, Lim/o;->g()Lim/q;

    .line 262
    .line 263
    .line 264
    iput-object v1, v7, Lim/l;->d:Lkotlin/jvm/internal/f0;

    .line 265
    .line 266
    iput-object v0, v7, Lim/l;->e:Lkotlin/jvm/internal/f0;

    .line 267
    .line 268
    iput v4, v7, Lim/l;->h:I

    .line 269
    .line 270
    check-cast v5, Ljm/a;

    .line 271
    .line 272
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 273
    .line 274
    .line 275
    new-instance v4, Lim/a;

    .line 276
    .line 277
    invoke-direct {v4, v6}, Lim/a;-><init>(Lim/r;)V

    .line 278
    .line 279
    .line 280
    if-ne v4, v8, :cond_9

    .line 281
    .line 282
    goto :goto_7

    .line 283
    :cond_9
    move-object v14, v4

    .line 284
    move-object v4, v0

    .line 285
    move-object v0, v14

    .line 286
    :goto_4
    check-cast v0, Lim/a;

    .line 287
    .line 288
    iget-object v5, v0, Lim/a;->a:Lim/r;

    .line 289
    .line 290
    if-eqz v5, :cond_a

    .line 291
    .line 292
    new-instance v4, Ldm/i;

    .line 293
    .line 294
    iget-object v5, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 295
    .line 296
    check-cast v5, Lcm/f;

    .line 297
    .line 298
    invoke-virtual {p0, v5}, Lim/o;->h(Lcm/f;)Lbm/p;

    .line 299
    .line 300
    .line 301
    move-result-object v2

    .line 302
    iget-object v0, v0, Lim/a;->a:Lim/r;

    .line 303
    .line 304
    iget-object v0, v0, Lim/r;->d:Lim/p;

    .line 305
    .line 306
    invoke-virtual {v0}, Lim/p;->a()Ljava/lang/String;

    .line 307
    .line 308
    .line 309
    move-result-object v0

    .line 310
    invoke-static {v3, v0}, Lim/o;->f(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 311
    .line 312
    .line 313
    move-result-object v0

    .line 314
    sget-object v3, Lbm/h;->f:Lbm/h;

    .line 315
    .line 316
    invoke-direct {v4, v2, v0, v3}, Ldm/i;-><init>(Lbm/q;Ljava/lang/String;Lbm/h;)V

    .line 317
    .line 318
    .line 319
    return-object v4

    .line 320
    :cond_a
    move-object v3, v4

    .line 321
    goto :goto_5

    .line 322
    :cond_b
    const-string v0, "snapshot is closed"

    .line 323
    .line 324
    new-instance v2, Ljava/lang/IllegalStateException;

    .line 325
    .line 326
    invoke-direct {v2, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 327
    .line 328
    .line 329
    throw v2

    .line 330
    :cond_c
    move-object v3, v0

    .line 331
    :goto_5
    invoke-virtual {p0}, Lim/o;->g()Lim/q;

    .line 332
    .line 333
    .line 334
    move-result-object v4

    .line 335
    new-instance v0, La7/k0;

    .line 336
    .line 337
    const/4 v5, 0x0

    .line 338
    const/4 v6, 0x6

    .line 339
    move-object v2, p0

    .line 340
    invoke-direct/range {v0 .. v6}, La7/k0;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 341
    .line 342
    .line 343
    iput-object v1, v7, Lim/l;->d:Lkotlin/jvm/internal/f0;

    .line 344
    .line 345
    iput-object v11, v7, Lim/l;->e:Lkotlin/jvm/internal/f0;

    .line 346
    .line 347
    iput v10, v7, Lim/l;->h:I

    .line 348
    .line 349
    invoke-virtual {p0, v4, v0, v7}, Lim/o;->d(Lim/q;Lay0/n;Lim/l;)Ljava/lang/Object;

    .line 350
    .line 351
    .line 352
    move-result-object v0

    .line 353
    if-ne v0, v8, :cond_d

    .line 354
    .line 355
    goto :goto_7

    .line 356
    :cond_d
    :goto_6
    check-cast v0, Ldm/i;

    .line 357
    .line 358
    if-nez v0, :cond_f

    .line 359
    .line 360
    invoke-virtual {p0}, Lim/o;->g()Lim/q;

    .line 361
    .line 362
    .line 363
    move-result-object v0

    .line 364
    new-instance v3, Lif0/d0;

    .line 365
    .line 366
    invoke-direct {v3, p0, v11, v9}, Lif0/d0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 367
    .line 368
    .line 369
    iput-object v1, v7, Lim/l;->d:Lkotlin/jvm/internal/f0;

    .line 370
    .line 371
    iput-object v11, v7, Lim/l;->e:Lkotlin/jvm/internal/f0;

    .line 372
    .line 373
    iput v9, v7, Lim/l;->h:I

    .line 374
    .line 375
    invoke-virtual {p0, v0, v3, v7}, Lim/o;->d(Lim/q;Lay0/n;Lim/l;)Ljava/lang/Object;

    .line 376
    .line 377
    .line 378
    move-result-object v0

    .line 379
    if-ne v0, v8, :cond_e

    .line 380
    .line 381
    :goto_7
    return-object v8

    .line 382
    :cond_e
    :goto_8
    check-cast v0, Ldm/i;
    :try_end_3
    .catch Ljava/lang/Exception; {:try_start_3 .. :try_end_3} :catch_0

    .line 383
    .line 384
    :cond_f
    return-object v0

    .line 385
    :goto_9
    iget-object v1, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 386
    .line 387
    check-cast v1, Lcm/f;

    .line 388
    .line 389
    if-eqz v1, :cond_10

    .line 390
    .line 391
    :try_start_4
    invoke-static {v1}, Lp3/m;->x(Ljava/lang/AutoCloseable;)V
    :try_end_4
    .catch Ljava/lang/RuntimeException; {:try_start_4 .. :try_end_4} :catch_2
    .catch Ljava/lang/Exception; {:try_start_4 .. :try_end_4} :catch_3

    .line 392
    .line 393
    .line 394
    goto :goto_a

    .line 395
    :catch_2
    move-exception v0

    .line 396
    throw v0

    .line 397
    :catch_3
    :cond_10
    :goto_a
    throw v0
.end method

.method public final d(Lim/q;Lay0/n;Lim/l;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget-object v0, p0, Lim/o;->b:Lmm/n;

    .line 2
    .line 3
    iget-object v0, v0, Lmm/n;->i:Lmm/b;

    .line 4
    .line 5
    iget-boolean v0, v0, Lmm/b;->d:Z

    .line 6
    .line 7
    if-eqz v0, :cond_1

    .line 8
    .line 9
    invoke-static {}, Landroid/os/Looper;->myLooper()Landroid/os/Looper;

    .line 10
    .line 11
    .line 12
    move-result-object v0

    .line 13
    invoke-static {}, Landroid/os/Looper;->getMainLooper()Landroid/os/Looper;

    .line 14
    .line 15
    .line 16
    move-result-object v1

    .line 17
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance p0, Landroid/os/NetworkOnMainThreadException;

    .line 25
    .line 26
    invoke-direct {p0}, Landroid/os/NetworkOnMainThreadException;-><init>()V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :cond_1
    :goto_0
    iget-object p0, p0, Lim/o;->c:Llx0/i;

    .line 31
    .line 32
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    check-cast p0, Llm/b;

    .line 37
    .line 38
    new-instance v0, Lim/k;

    .line 39
    .line 40
    const/4 v1, 0x0

    .line 41
    const/4 v2, 0x0

    .line 42
    invoke-direct {v0, p2, v1, v2}, Lim/k;-><init>(Lay0/n;Lkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Llm/b;->a:Ld01/i;

    .line 46
    .line 47
    invoke-static {p0, p1, v0, p3}, Llm/b;->a(Ld01/i;Lim/q;Lim/k;Lrx0/c;)Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    return-object p0
.end method

.method public final e()Lu01/k;
    .locals 1

    .line 1
    iget-object v0, p0, Lim/o;->d:Llx0/q;

    .line 2
    .line 3
    invoke-virtual {v0}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lcm/g;

    .line 8
    .line 9
    if-eqz v0, :cond_1

    .line 10
    .line 11
    iget-object v0, v0, Lcm/g;->a:Lu01/k;

    .line 12
    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    return-object v0

    .line 17
    :cond_1
    :goto_0
    iget-object p0, p0, Lim/o;->b:Lmm/n;

    .line 18
    .line 19
    iget-object p0, p0, Lmm/n;->f:Lu01/k;

    .line 20
    .line 21
    return-object p0
.end method

.method public final g()Lim/q;
    .locals 5

    .line 1
    sget-object v0, Lim/h;->b:Ld8/c;

    .line 2
    .line 3
    iget-object v1, p0, Lim/o;->b:Lmm/n;

    .line 4
    .line 5
    invoke-static {v1, v0}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    check-cast v0, Lim/p;

    .line 10
    .line 11
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 12
    .line 13
    .line 14
    new-instance v2, La7/o1;

    .line 15
    .line 16
    invoke-direct {v2, v0}, La7/o1;-><init>(Lim/p;)V

    .line 17
    .line 18
    .line 19
    iget-object v0, v1, Lmm/n;->h:Lmm/b;

    .line 20
    .line 21
    iget-boolean v3, v0, Lmm/b;->d:Z

    .line 22
    .line 23
    iget-object v4, v1, Lmm/n;->i:Lmm/b;

    .line 24
    .line 25
    iget-boolean v4, v4, Lmm/b;->d:Z

    .line 26
    .line 27
    if-eqz v4, :cond_0

    .line 28
    .line 29
    iget-object v4, p0, Lim/o;->f:Lim/e;

    .line 30
    .line 31
    invoke-interface {v4}, Lim/e;->d()Z

    .line 32
    .line 33
    .line 34
    move-result v4

    .line 35
    if-eqz v4, :cond_0

    .line 36
    .line 37
    const/4 v4, 0x1

    .line 38
    goto :goto_0

    .line 39
    :cond_0
    const/4 v4, 0x0

    .line 40
    :goto_0
    if-nez v4, :cond_1

    .line 41
    .line 42
    if-eqz v3, :cond_1

    .line 43
    .line 44
    const-string v0, "only-if-cached, max-stale=2147483647"

    .line 45
    .line 46
    invoke-virtual {v2, v0}, La7/o1;->b(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_1
    if-eqz v4, :cond_3

    .line 51
    .line 52
    if-nez v3, :cond_3

    .line 53
    .line 54
    iget-boolean v0, v0, Lmm/b;->e:Z

    .line 55
    .line 56
    if-eqz v0, :cond_2

    .line 57
    .line 58
    const-string v0, "no-cache"

    .line 59
    .line 60
    invoke-virtual {v2, v0}, La7/o1;->b(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_2
    const-string v0, "no-cache, no-store"

    .line 65
    .line 66
    invoke-virtual {v2, v0}, La7/o1;->b(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    goto :goto_1

    .line 70
    :cond_3
    if-nez v4, :cond_4

    .line 71
    .line 72
    if-nez v3, :cond_4

    .line 73
    .line 74
    const-string v0, "no-cache, only-if-cached"

    .line 75
    .line 76
    invoke-virtual {v2, v0}, La7/o1;->b(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    :cond_4
    :goto_1
    new-instance v0, Lim/q;

    .line 80
    .line 81
    sget-object v3, Lim/h;->a:Ld8/c;

    .line 82
    .line 83
    invoke-static {v1, v3}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 84
    .line 85
    .line 86
    move-result-object v3

    .line 87
    check-cast v3, Ljava/lang/String;

    .line 88
    .line 89
    new-instance v4, Lim/p;

    .line 90
    .line 91
    iget-object v2, v2, La7/o1;->a:Ljava/util/LinkedHashMap;

    .line 92
    .line 93
    invoke-static {v2}, Lmx0/x;->u(Ljava/util/Map;)Ljava/util/Map;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    invoke-direct {v4, v2}, Lim/p;-><init>(Ljava/util/Map;)V

    .line 98
    .line 99
    .line 100
    sget-object v2, Lim/h;->c:Ld8/c;

    .line 101
    .line 102
    invoke-static {v1, v2}, Lyl/m;->e(Lmm/n;Ld8/c;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    if-nez v2, :cond_5

    .line 107
    .line 108
    iget-object v1, v1, Lmm/n;->j:Lyl/i;

    .line 109
    .line 110
    iget-object p0, p0, Lim/o;->a:Ljava/lang/String;

    .line 111
    .line 112
    invoke-direct {v0, p0, v3, v4, v1}, Lim/q;-><init>(Ljava/lang/String;Ljava/lang/String;Lim/p;Lyl/i;)V

    .line 113
    .line 114
    .line 115
    return-object v0

    .line 116
    :cond_5
    new-instance p0, Ljava/lang/ClassCastException;

    .line 117
    .line 118
    invoke-direct {p0}, Ljava/lang/ClassCastException;-><init>()V

    .line 119
    .line 120
    .line 121
    throw p0
.end method

.method public final h(Lcm/f;)Lbm/p;
    .locals 3

    .line 1
    iget-object v0, p1, Lcm/f;->d:Lcm/b;

    .line 2
    .line 3
    iget-boolean v1, v0, Lcm/b;->e:Z

    .line 4
    .line 5
    if-nez v1, :cond_1

    .line 6
    .line 7
    iget-object v0, v0, Lcm/b;->d:Lcm/a;

    .line 8
    .line 9
    iget-object v0, v0, Lcm/a;->c:Ljava/util/ArrayList;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object v0

    .line 16
    check-cast v0, Lu01/y;

    .line 17
    .line 18
    invoke-virtual {p0}, Lim/o;->e()Lu01/k;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    iget-object v2, p0, Lim/o;->b:Lmm/n;

    .line 23
    .line 24
    iget-object v2, v2, Lmm/n;->e:Ljava/lang/String;

    .line 25
    .line 26
    if-nez v2, :cond_0

    .line 27
    .line 28
    iget-object v2, p0, Lim/o;->a:Ljava/lang/String;

    .line 29
    .line 30
    :cond_0
    const/16 p0, 0x10

    .line 31
    .line 32
    invoke-static {v0, v1, v2, p1, p0}, Ljp/va;->a(Lu01/y;Lu01/k;Ljava/lang/String;Lcm/f;I)Lbm/p;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    const-string p1, "snapshot is closed"

    .line 40
    .line 41
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0
.end method

.method public final i(Lcm/f;)Lim/r;
    .locals 2

    .line 1
    const/4 v0, 0x0

    .line 2
    :try_start_0
    invoke-virtual {p0}, Lim/o;->e()Lu01/k;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    iget-object p1, p1, Lcm/f;->d:Lcm/b;

    .line 7
    .line 8
    iget-boolean v1, p1, Lcm/b;->e:Z

    .line 9
    .line 10
    if-nez v1, :cond_1

    .line 11
    .line 12
    iget-object p1, p1, Lcm/b;->d:Lcm/a;

    .line 13
    .line 14
    iget-object p1, p1, Lcm/a;->c:Ljava/util/ArrayList;

    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    invoke-virtual {p1, v1}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p1

    .line 21
    check-cast p1, Lu01/y;

    .line 22
    .line 23
    invoke-virtual {p0, p1}, Lu01/k;->H(Lu01/y;)Lu01/h0;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    invoke-static {p0}, Lu01/b;->c(Lu01/h0;)Lu01/b0;

    .line 28
    .line 29
    .line 30
    move-result-object p0
    :try_end_0
    .catch Ljava/io/IOException; {:try_start_0 .. :try_end_0} :catch_0

    .line 31
    :try_start_1
    invoke-static {p0}, Llp/na;->e(Lu01/b0;)Lim/r;

    .line 32
    .line 33
    .line 34
    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 35
    :try_start_2
    invoke-virtual {p0}, Lu01/b0;->close()V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 36
    .line 37
    .line 38
    move-object p0, v0

    .line 39
    goto :goto_1

    .line 40
    :catchall_0
    move-exception p0

    .line 41
    goto :goto_1

    .line 42
    :catchall_1
    move-exception p1

    .line 43
    :try_start_3
    invoke-virtual {p0}, Lu01/b0;->close()V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 44
    .line 45
    .line 46
    goto :goto_0

    .line 47
    :catchall_2
    move-exception p0

    .line 48
    :try_start_4
    invoke-static {p1, p0}, Loa0/b;->a(Ljava/lang/Throwable;Ljava/lang/Throwable;)V

    .line 49
    .line 50
    .line 51
    :goto_0
    move-object p0, p1

    .line 52
    move-object p1, v0

    .line 53
    :goto_1
    if-nez p0, :cond_0

    .line 54
    .line 55
    return-object p1

    .line 56
    :cond_0
    throw p0

    .line 57
    :cond_1
    const-string p0, "snapshot is closed"

    .line 58
    .line 59
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p1
    :try_end_4
    .catch Ljava/io/IOException; {:try_start_4 .. :try_end_4} :catch_0

    .line 65
    :catch_0
    return-object v0
.end method
