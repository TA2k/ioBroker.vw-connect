.class public final Lfb/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lmb/o;

.field public final b:Landroid/content/Context;

.field public final c:Ljava/lang/String;

.field public final d:Lob/a;

.field public final e:Leb/b;

.field public final f:Leb/j;

.field public final g:Llb/a;

.field public final h:Landroidx/work/impl/WorkDatabase;

.field public final i:Lmb/s;

.field public final j:Lmb/b;

.field public final k:Ljava/util/ArrayList;

.field public final l:Ljava/lang/String;

.field public final m:Lvy0/k1;


# direct methods
.method public constructor <init>(Lss/b;)V
    .locals 7

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iget-object v0, p1, Lss/b;->i:Ljava/lang/Object;

    .line 5
    .line 6
    check-cast v0, Lmb/o;

    .line 7
    .line 8
    iput-object v0, p0, Lfb/f0;->a:Lmb/o;

    .line 9
    .line 10
    iget-object v1, p1, Lss/b;->k:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Landroid/content/Context;

    .line 13
    .line 14
    iput-object v1, p0, Lfb/f0;->b:Landroid/content/Context;

    .line 15
    .line 16
    iget-object v0, v0, Lmb/o;->a:Ljava/lang/String;

    .line 17
    .line 18
    iput-object v0, p0, Lfb/f0;->c:Ljava/lang/String;

    .line 19
    .line 20
    iget-object v1, p1, Lss/b;->f:Ljava/lang/Object;

    .line 21
    .line 22
    check-cast v1, Lob/a;

    .line 23
    .line 24
    iput-object v1, p0, Lfb/f0;->d:Lob/a;

    .line 25
    .line 26
    iget-object v1, p1, Lss/b;->e:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v1, Leb/b;

    .line 29
    .line 30
    iput-object v1, p0, Lfb/f0;->e:Leb/b;

    .line 31
    .line 32
    iget-object v1, v1, Leb/b;->d:Leb/j;

    .line 33
    .line 34
    iput-object v1, p0, Lfb/f0;->f:Leb/j;

    .line 35
    .line 36
    iget-object v1, p1, Lss/b;->g:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v1, Llb/a;

    .line 39
    .line 40
    iput-object v1, p0, Lfb/f0;->g:Llb/a;

    .line 41
    .line 42
    iget-object v1, p1, Lss/b;->h:Ljava/lang/Object;

    .line 43
    .line 44
    check-cast v1, Landroidx/work/impl/WorkDatabase;

    .line 45
    .line 46
    iput-object v1, p0, Lfb/f0;->h:Landroidx/work/impl/WorkDatabase;

    .line 47
    .line 48
    invoke-virtual {v1}, Landroidx/work/impl/WorkDatabase;->x()Lmb/s;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    iput-object v2, p0, Lfb/f0;->i:Lmb/s;

    .line 53
    .line 54
    invoke-virtual {v1}, Landroidx/work/impl/WorkDatabase;->s()Lmb/b;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    iput-object v1, p0, Lfb/f0;->j:Lmb/b;

    .line 59
    .line 60
    iget-object p1, p1, Lss/b;->j:Ljava/lang/Object;

    .line 61
    .line 62
    move-object v1, p1

    .line 63
    check-cast v1, Ljava/util/ArrayList;

    .line 64
    .line 65
    iput-object v1, p0, Lfb/f0;->k:Ljava/util/ArrayList;

    .line 66
    .line 67
    const-string p1, "Work [ id="

    .line 68
    .line 69
    const-string v2, ", tags={ "

    .line 70
    .line 71
    invoke-static {p1, v0, v2}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    const/4 v5, 0x0

    .line 76
    const/16 v6, 0x3e

    .line 77
    .line 78
    const-string v2, ","

    .line 79
    .line 80
    const/4 v3, 0x0

    .line 81
    const/4 v4, 0x0

    .line 82
    invoke-static/range {v1 .. v6}, Lmx0/q;->R(Ljava/lang/Iterable;Ljava/lang/CharSequence;Ljava/lang/String;Ljava/lang/String;Lay0/k;I)Ljava/lang/String;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    const-string v1, " } ]"

    .line 87
    .line 88
    invoke-static {p1, v0, v1}, La7/g0;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    iput-object p1, p0, Lfb/f0;->l:Ljava/lang/String;

    .line 93
    .line 94
    invoke-static {}, Lvy0/e0;->d()Lvy0/k1;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    iput-object p1, p0, Lfb/f0;->m:Lvy0/k1;

    .line 99
    .line 100
    return-void
.end method

.method public static final a(Lfb/f0;Lrx0/c;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v2, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    iget-object v6, v2, Lfb/f0;->l:Ljava/lang/String;

    .line 6
    .line 7
    iget-object v1, v2, Lfb/f0;->c:Ljava/lang/String;

    .line 8
    .line 9
    iget-object v7, v2, Lfb/f0;->d:Lob/a;

    .line 10
    .line 11
    iget-object v8, v2, Lfb/f0;->h:Landroidx/work/impl/WorkDatabase;

    .line 12
    .line 13
    iget-object v3, v2, Lfb/f0;->e:Leb/b;

    .line 14
    .line 15
    iget-object v4, v3, Leb/b;->m:Leb/j;

    .line 16
    .line 17
    iget-object v5, v2, Lfb/f0;->a:Lmb/o;

    .line 18
    .line 19
    instance-of v9, v0, Lfb/e0;

    .line 20
    .line 21
    if-eqz v9, :cond_0

    .line 22
    .line 23
    move-object v9, v0

    .line 24
    check-cast v9, Lfb/e0;

    .line 25
    .line 26
    iget v10, v9, Lfb/e0;->f:I

    .line 27
    .line 28
    const/high16 v11, -0x80000000

    .line 29
    .line 30
    and-int v12, v10, v11

    .line 31
    .line 32
    if-eqz v12, :cond_0

    .line 33
    .line 34
    sub-int/2addr v10, v11

    .line 35
    iput v10, v9, Lfb/e0;->f:I

    .line 36
    .line 37
    goto :goto_0

    .line 38
    :cond_0
    new-instance v9, Lfb/e0;

    .line 39
    .line 40
    invoke-direct {v9, v2, v0}, Lfb/e0;-><init>(Lfb/f0;Lrx0/c;)V

    .line 41
    .line 42
    .line 43
    :goto_0
    iget-object v0, v9, Lfb/e0;->d:Ljava/lang/Object;

    .line 44
    .line 45
    sget-object v10, Lqx0/a;->d:Lqx0/a;

    .line 46
    .line 47
    iget v11, v9, Lfb/e0;->f:I

    .line 48
    .line 49
    const/4 v12, 0x1

    .line 50
    if-eqz v11, :cond_2

    .line 51
    .line 52
    if-ne v11, v12, :cond_1

    .line 53
    .line 54
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 55
    .line 56
    .line 57
    move-object/from16 v16, v6

    .line 58
    .line 59
    goto/16 :goto_4

    .line 60
    .line 61
    :catchall_0
    move-exception v0

    .line 62
    move-object/from16 v16, v6

    .line 63
    .line 64
    goto/16 :goto_5

    .line 65
    .line 66
    :catch_0
    move-exception v0

    .line 67
    move-object v4, v6

    .line 68
    goto/16 :goto_6

    .line 69
    .line 70
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 71
    .line 72
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 73
    .line 74
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 75
    .line 76
    .line 77
    throw v0

    .line 78
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    iget-object v11, v3, Leb/b;->e:Leb/j;

    .line 82
    .line 83
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 84
    .line 85
    .line 86
    invoke-static {}, Lab/a;->a()Z

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    iget-object v13, v5, Lmb/o;->x:Ljava/lang/String;

    .line 91
    .line 92
    iget-object v14, v5, Lmb/o;->c:Ljava/lang/String;

    .line 93
    .line 94
    iget-object v15, v5, Lmb/o;->d:Ljava/lang/String;

    .line 95
    .line 96
    if-eqz v4, :cond_3

    .line 97
    .line 98
    if-eqz v13, :cond_3

    .line 99
    .line 100
    invoke-virtual {v5}, Lmb/o;->hashCode()I

    .line 101
    .line 102
    .line 103
    move-result v0

    .line 104
    invoke-static {v13}, Ljp/x0;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 105
    .line 106
    .line 107
    move-result-object v12

    .line 108
    invoke-static {v12, v0}, Landroid/os/Trace;->beginAsyncSection(Ljava/lang/String;I)V

    .line 109
    .line 110
    .line 111
    :cond_3
    new-instance v0, Lfb/y;

    .line 112
    .line 113
    const/4 v12, 0x0

    .line 114
    invoke-direct {v0, v2, v12}, Lfb/y;-><init>(Lfb/f0;I)V

    .line 115
    .line 116
    .line 117
    new-instance v12, Lh50/q0;

    .line 118
    .line 119
    move-object/from16 v17, v13

    .line 120
    .line 121
    const/16 v13, 0x17

    .line 122
    .line 123
    invoke-direct {v12, v0, v13}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v8, v12}, Lla/u;->p(Lay0/a;)Ljava/lang/Object;

    .line 127
    .line 128
    .line 129
    move-result-object v0

    .line 130
    check-cast v0, Ljava/lang/Boolean;

    .line 131
    .line 132
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 133
    .line 134
    .line 135
    move-result v0

    .line 136
    if-eqz v0, :cond_4

    .line 137
    .line 138
    new-instance v0, Lfb/b0;

    .line 139
    .line 140
    invoke-direct {v0}, Lfb/b0;-><init>()V

    .line 141
    .line 142
    .line 143
    return-object v0

    .line 144
    :cond_4
    invoke-virtual {v5}, Lmb/o;->b()Z

    .line 145
    .line 146
    .line 147
    move-result v0

    .line 148
    const/4 v12, 0x0

    .line 149
    if-eqz v0, :cond_5

    .line 150
    .line 151
    iget-object v0, v5, Lmb/o;->e:Leb/h;

    .line 152
    .line 153
    move/from16 v18, v4

    .line 154
    .line 155
    goto/16 :goto_3

    .line 156
    .line 157
    :cond_5
    iget-object v0, v3, Leb/b;->f:Leb/j;

    .line 158
    .line 159
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 160
    .line 161
    .line 162
    const-string v0, "className"

    .line 163
    .line 164
    invoke-static {v15, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    sget-object v0, Leb/o;->a:Ljava/lang/String;

    .line 168
    .line 169
    :try_start_1
    invoke-static {v15}, Ljava/lang/Class;->forName(Ljava/lang/String;)Ljava/lang/Class;

    .line 170
    .line 171
    .line 172
    move-result-object v0

    .line 173
    invoke-virtual {v0, v12}, Ljava/lang/Class;->getDeclaredConstructor([Ljava/lang/Class;)Ljava/lang/reflect/Constructor;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    invoke-virtual {v0, v12}, Ljava/lang/reflect/Constructor;->newInstance([Ljava/lang/Object;)Ljava/lang/Object;

    .line 178
    .line 179
    .line 180
    move-result-object v0

    .line 181
    const-string v12, "null cannot be cast to non-null type androidx.work.InputMerger"

    .line 182
    .line 183
    invoke-static {v0, v12}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 184
    .line 185
    .line 186
    check-cast v0, Landroidx/work/OverwritingInputMerger;
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 187
    .line 188
    move/from16 v18, v4

    .line 189
    .line 190
    goto :goto_1

    .line 191
    :catch_1
    move-exception v0

    .line 192
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 193
    .line 194
    .line 195
    move-result-object v12

    .line 196
    sget-object v13, Leb/o;->a:Ljava/lang/String;

    .line 197
    .line 198
    move/from16 v18, v4

    .line 199
    .line 200
    const-string v4, "Trouble instantiating "

    .line 201
    .line 202
    invoke-virtual {v4, v15}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 203
    .line 204
    .line 205
    move-result-object v4

    .line 206
    invoke-virtual {v12, v13, v4, v0}, Leb/w;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 207
    .line 208
    .line 209
    const/4 v0, 0x0

    .line 210
    :goto_1
    if-nez v0, :cond_6

    .line 211
    .line 212
    sget-object v0, Lfb/g0;->a:Ljava/lang/String;

    .line 213
    .line 214
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 215
    .line 216
    .line 217
    move-result-object v1

    .line 218
    const-string v2, "Could not create Input Merger "

    .line 219
    .line 220
    invoke-virtual {v2, v15}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v2

    .line 224
    invoke-virtual {v1, v0, v2}, Leb/w;->b(Ljava/lang/String;Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    new-instance v10, Lfb/z;

    .line 228
    .line 229
    invoke-direct {v10}, Lfb/z;-><init>()V

    .line 230
    .line 231
    .line 232
    goto/16 :goto_7

    .line 233
    .line 234
    :cond_6
    iget-object v0, v5, Lmb/o;->e:Leb/h;

    .line 235
    .line 236
    invoke-static {v0}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 237
    .line 238
    .line 239
    move-result-object v0

    .line 240
    check-cast v0, Ljava/util/Collection;

    .line 241
    .line 242
    iget-object v4, v2, Lfb/f0;->i:Lmb/s;

    .line 243
    .line 244
    invoke-virtual {v4}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 245
    .line 246
    .line 247
    const-string v12, "id"

    .line 248
    .line 249
    invoke-static {v1, v12}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 250
    .line 251
    .line 252
    iget-object v4, v4, Lmb/s;->a:Lla/u;

    .line 253
    .line 254
    new-instance v12, Lif0/d;

    .line 255
    .line 256
    const/16 v13, 0x17

    .line 257
    .line 258
    invoke-direct {v12, v1, v13}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 259
    .line 260
    .line 261
    const/4 v13, 0x0

    .line 262
    const/4 v15, 0x1

    .line 263
    invoke-static {v4, v15, v13, v12}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 264
    .line 265
    .line 266
    move-result-object v4

    .line 267
    check-cast v4, Ljava/util/List;

    .line 268
    .line 269
    check-cast v4, Ljava/lang/Iterable;

    .line 270
    .line 271
    invoke-static {v4, v0}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 272
    .line 273
    .line 274
    move-result-object v0

    .line 275
    new-instance v4, Leb/c0;

    .line 276
    .line 277
    invoke-direct {v4}, Leb/c0;-><init>()V

    .line 278
    .line 279
    .line 280
    new-instance v12, Ljava/util/LinkedHashMap;

    .line 281
    .line 282
    invoke-direct {v12}, Ljava/util/LinkedHashMap;-><init>()V

    .line 283
    .line 284
    .line 285
    invoke-virtual {v0}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 286
    .line 287
    .line 288
    move-result-object v0

    .line 289
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 290
    .line 291
    .line 292
    move-result v13

    .line 293
    if-eqz v13, :cond_7

    .line 294
    .line 295
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 296
    .line 297
    .line 298
    move-result-object v13

    .line 299
    check-cast v13, Leb/h;

    .line 300
    .line 301
    iget-object v13, v13, Leb/h;->a:Ljava/util/HashMap;

    .line 302
    .line 303
    invoke-static {v13}, Ljava/util/Collections;->unmodifiableMap(Ljava/util/Map;)Ljava/util/Map;

    .line 304
    .line 305
    .line 306
    move-result-object v13

    .line 307
    const-string v15, "unmodifiableMap(...)"

    .line 308
    .line 309
    invoke-static {v13, v15}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 310
    .line 311
    .line 312
    invoke-interface {v12, v13}, Ljava/util/Map;->putAll(Ljava/util/Map;)V

    .line 313
    .line 314
    .line 315
    goto :goto_2

    .line 316
    :cond_7
    invoke-virtual {v4, v12}, Leb/c0;->b(Ljava/util/HashMap;)V

    .line 317
    .line 318
    .line 319
    new-instance v0, Leb/h;

    .line 320
    .line 321
    iget-object v4, v4, Leb/c0;->a:Ljava/lang/Object;

    .line 322
    .line 323
    check-cast v4, Ljava/util/LinkedHashMap;

    .line 324
    .line 325
    invoke-direct {v0, v4}, Leb/h;-><init>(Ljava/util/LinkedHashMap;)V

    .line 326
    .line 327
    .line 328
    invoke-static {v0}, Lkp/b6;->d(Leb/h;)[B

    .line 329
    .line 330
    .line 331
    :goto_3
    new-instance v4, Landroidx/work/WorkerParameters;

    .line 332
    .line 333
    invoke-static {v1}, Ljava/util/UUID;->fromString(Ljava/lang/String;)Ljava/util/UUID;

    .line 334
    .line 335
    .line 336
    move-result-object v1

    .line 337
    iget-object v12, v2, Lfb/f0;->k:Ljava/util/ArrayList;

    .line 338
    .line 339
    iget v5, v5, Lmb/o;->k:I

    .line 340
    .line 341
    iget-object v13, v3, Leb/b;->a:Ljava/util/concurrent/ExecutorService;

    .line 342
    .line 343
    iget-object v3, v3, Leb/b;->b:Lcz0/e;

    .line 344
    .line 345
    new-instance v15, Lnb/m;

    .line 346
    .line 347
    new-instance v15, Lnb/l;

    .line 348
    .line 349
    move-object/from16 v16, v6

    .line 350
    .line 351
    iget-object v6, v2, Lfb/f0;->g:Llb/a;

    .line 352
    .line 353
    invoke-direct {v15, v8, v6, v7}, Lnb/l;-><init>(Landroidx/work/impl/WorkDatabase;Llb/a;Lob/a;)V

    .line 354
    .line 355
    .line 356
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 357
    .line 358
    .line 359
    iput-object v1, v4, Landroidx/work/WorkerParameters;->a:Ljava/util/UUID;

    .line 360
    .line 361
    iput-object v0, v4, Landroidx/work/WorkerParameters;->b:Leb/h;

    .line 362
    .line 363
    new-instance v0, Ljava/util/HashSet;

    .line 364
    .line 365
    invoke-direct {v0, v12}, Ljava/util/HashSet;-><init>(Ljava/util/Collection;)V

    .line 366
    .line 367
    .line 368
    iput v5, v4, Landroidx/work/WorkerParameters;->c:I

    .line 369
    .line 370
    iput-object v13, v4, Landroidx/work/WorkerParameters;->d:Ljava/util/concurrent/ExecutorService;

    .line 371
    .line 372
    iput-object v3, v4, Landroidx/work/WorkerParameters;->e:Lpx0/g;

    .line 373
    .line 374
    :try_start_2
    iget-object v0, v2, Lfb/f0;->b:Landroid/content/Context;

    .line 375
    .line 376
    invoke-virtual {v11, v0, v14, v4}, Leb/j;->a(Landroid/content/Context;Ljava/lang/String;Landroidx/work/WorkerParameters;)Leb/v;

    .line 377
    .line 378
    .line 379
    move-result-object v1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 380
    const/4 v6, 0x1

    .line 381
    iput-boolean v6, v1, Leb/v;->g:Z

    .line 382
    .line 383
    invoke-interface {v9}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 384
    .line 385
    .line 386
    move-result-object v0

    .line 387
    sget-object v3, Lvy0/h1;->d:Lvy0/h1;

    .line 388
    .line 389
    invoke-interface {v0, v3}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 390
    .line 391
    .line 392
    move-result-object v0

    .line 393
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 394
    .line 395
    .line 396
    move-object v11, v0

    .line 397
    check-cast v11, Lvy0/i1;

    .line 398
    .line 399
    new-instance v0, Le2/g;

    .line 400
    .line 401
    const/4 v5, 0x1

    .line 402
    move-object v4, v2

    .line 403
    move-object/from16 v3, v17

    .line 404
    .line 405
    move/from16 v2, v18

    .line 406
    .line 407
    invoke-direct/range {v0 .. v5}, Le2/g;-><init>(Ljava/lang/Object;ZLjava/lang/Object;Ljava/lang/Object;I)V

    .line 408
    .line 409
    .line 410
    move-object v2, v4

    .line 411
    invoke-interface {v11, v0}, Lvy0/i1;->E(Lay0/k;)Lvy0/r0;

    .line 412
    .line 413
    .line 414
    new-instance v0, Lfb/y;

    .line 415
    .line 416
    invoke-direct {v0, v2, v6}, Lfb/y;-><init>(Lfb/f0;I)V

    .line 417
    .line 418
    .line 419
    new-instance v3, Lh50/q0;

    .line 420
    .line 421
    const/16 v13, 0x17

    .line 422
    .line 423
    invoke-direct {v3, v0, v13}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 424
    .line 425
    .line 426
    invoke-virtual {v8, v3}, Lla/u;->p(Lay0/a;)Ljava/lang/Object;

    .line 427
    .line 428
    .line 429
    move-result-object v0

    .line 430
    const-string v3, "runInTransaction(...)"

    .line 431
    .line 432
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 433
    .line 434
    .line 435
    check-cast v0, Ljava/lang/Boolean;

    .line 436
    .line 437
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 438
    .line 439
    .line 440
    move-result v0

    .line 441
    if-nez v0, :cond_8

    .line 442
    .line 443
    new-instance v10, Lfb/b0;

    .line 444
    .line 445
    invoke-direct {v10}, Lfb/b0;-><init>()V

    .line 446
    .line 447
    .line 448
    goto/16 :goto_7

    .line 449
    .line 450
    :cond_8
    invoke-interface {v11}, Lvy0/i1;->isCancelled()Z

    .line 451
    .line 452
    .line 453
    move-result v0

    .line 454
    if-eqz v0, :cond_9

    .line 455
    .line 456
    new-instance v10, Lfb/b0;

    .line 457
    .line 458
    invoke-direct {v10}, Lfb/b0;-><init>()V

    .line 459
    .line 460
    .line 461
    goto/16 :goto_7

    .line 462
    .line 463
    :cond_9
    iget-object v0, v7, Lob/a;->d:Lj0/e;

    .line 464
    .line 465
    const-string v3, "getMainThreadExecutor(...)"

    .line 466
    .line 467
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 468
    .line 469
    .line 470
    invoke-static {v0}, Lvy0/e0;->t(Ljava/util/concurrent/Executor;)Lvy0/x;

    .line 471
    .line 472
    .line 473
    move-result-object v6

    .line 474
    :try_start_3
    new-instance v0, Le1/e;

    .line 475
    .line 476
    move-object v3, v1

    .line 477
    const/16 v1, 0x14

    .line 478
    .line 479
    move-object v4, v15

    .line 480
    const/4 v5, 0x0

    .line 481
    invoke-direct/range {v0 .. v5}, Le1/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 482
    .line 483
    .line 484
    const/4 v15, 0x1

    .line 485
    iput v15, v9, Lfb/e0;->f:I

    .line 486
    .line 487
    invoke-static {v6, v0, v9}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 488
    .line 489
    .line 490
    move-result-object v0

    .line 491
    if-ne v0, v10, :cond_a

    .line 492
    .line 493
    goto :goto_7

    .line 494
    :cond_a
    :goto_4
    check-cast v0, Leb/u;

    .line 495
    .line 496
    new-instance v10, Lfb/a0;

    .line 497
    .line 498
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 499
    .line 500
    .line 501
    invoke-direct {v10, v0}, Lfb/a0;-><init>(Leb/u;)V
    :try_end_3
    .catch Ljava/util/concurrent/CancellationException; {:try_start_3 .. :try_end_3} :catch_2
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 502
    .line 503
    .line 504
    goto :goto_7

    .line 505
    :catchall_1
    move-exception v0

    .line 506
    goto :goto_5

    .line 507
    :catch_2
    move-exception v0

    .line 508
    move-object/from16 v4, v16

    .line 509
    .line 510
    goto :goto_6

    .line 511
    :goto_5
    sget-object v1, Lfb/g0;->a:Ljava/lang/String;

    .line 512
    .line 513
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 514
    .line 515
    .line 516
    move-result-object v2

    .line 517
    new-instance v3, Ljava/lang/StringBuilder;

    .line 518
    .line 519
    invoke-direct {v3}, Ljava/lang/StringBuilder;-><init>()V

    .line 520
    .line 521
    .line 522
    move-object/from16 v4, v16

    .line 523
    .line 524
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 525
    .line 526
    .line 527
    const-string v4, " failed because it threw an exception/error"

    .line 528
    .line 529
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 530
    .line 531
    .line 532
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 533
    .line 534
    .line 535
    move-result-object v3

    .line 536
    invoke-virtual {v2, v1, v3, v0}, Leb/w;->c(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 537
    .line 538
    .line 539
    new-instance v10, Lfb/z;

    .line 540
    .line 541
    invoke-direct {v10}, Lfb/z;-><init>()V

    .line 542
    .line 543
    .line 544
    goto :goto_7

    .line 545
    :goto_6
    sget-object v1, Lfb/g0;->a:Ljava/lang/String;

    .line 546
    .line 547
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 548
    .line 549
    .line 550
    move-result-object v2

    .line 551
    const-string v3, " was cancelled"

    .line 552
    .line 553
    invoke-static {v4, v3}, Lf2/m0;->h(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 554
    .line 555
    .line 556
    move-result-object v3

    .line 557
    iget v2, v2, Leb/w;->a:I

    .line 558
    .line 559
    const/4 v4, 0x4

    .line 560
    if-gt v2, v4, :cond_b

    .line 561
    .line 562
    invoke-static {v1, v3, v0}, Landroid/util/Log;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 563
    .line 564
    .line 565
    :cond_b
    throw v0

    .line 566
    :catchall_2
    sget-object v0, Lfb/g0;->a:Ljava/lang/String;

    .line 567
    .line 568
    invoke-static {}, Leb/w;->d()Leb/w;

    .line 569
    .line 570
    .line 571
    move-result-object v1

    .line 572
    new-instance v2, Ljava/lang/StringBuilder;

    .line 573
    .line 574
    const-string v3, "Could not create Worker "

    .line 575
    .line 576
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 577
    .line 578
    .line 579
    invoke-virtual {v2, v14}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 580
    .line 581
    .line 582
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 583
    .line 584
    .line 585
    move-result-object v2

    .line 586
    invoke-virtual {v1, v0, v2}, Leb/w;->b(Ljava/lang/String;Ljava/lang/String;)V

    .line 587
    .line 588
    .line 589
    new-instance v10, Lfb/z;

    .line 590
    .line 591
    invoke-direct {v10}, Lfb/z;-><init>()V

    .line 592
    .line 593
    .line 594
    :goto_7
    return-object v10
.end method


# virtual methods
.method public final b(I)V
    .locals 5

    .line 1
    sget-object v0, Leb/h0;->d:Leb/h0;

    .line 2
    .line 3
    iget-object v1, p0, Lfb/f0;->i:Lmb/s;

    .line 4
    .line 5
    iget-object v2, p0, Lfb/f0;->c:Ljava/lang/String;

    .line 6
    .line 7
    invoke-virtual {v1, v0, v2}, Lmb/s;->j(Leb/h0;Ljava/lang/String;)I

    .line 8
    .line 9
    .line 10
    iget-object v0, p0, Lfb/f0;->f:Leb/j;

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 13
    .line 14
    .line 15
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 16
    .line 17
    .line 18
    move-result-wide v3

    .line 19
    invoke-virtual {v1, v3, v4, v2}, Lmb/s;->i(JLjava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Lfb/f0;->a:Lmb/o;

    .line 23
    .line 24
    iget p0, p0, Lmb/o;->v:I

    .line 25
    .line 26
    invoke-virtual {v1, p0, v2}, Lmb/s;->h(ILjava/lang/String;)V

    .line 27
    .line 28
    .line 29
    const-wide/16 v3, -0x1

    .line 30
    .line 31
    invoke-virtual {v1, v3, v4, v2}, Lmb/s;->g(JLjava/lang/String;)I

    .line 32
    .line 33
    .line 34
    invoke-virtual {v1, p1, v2}, Lmb/s;->k(ILjava/lang/String;)V

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public final c()V
    .locals 6

    .line 1
    iget-object v0, p0, Lfb/f0;->f:Leb/j;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 4
    .line 5
    .line 6
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    iget-object v2, p0, Lfb/f0;->i:Lmb/s;

    .line 11
    .line 12
    iget-object v3, p0, Lfb/f0;->c:Ljava/lang/String;

    .line 13
    .line 14
    invoke-virtual {v2, v0, v1, v3}, Lmb/s;->i(JLjava/lang/String;)V

    .line 15
    .line 16
    .line 17
    sget-object v0, Leb/h0;->d:Leb/h0;

    .line 18
    .line 19
    invoke-virtual {v2, v0, v3}, Lmb/s;->j(Leb/h0;Ljava/lang/String;)I

    .line 20
    .line 21
    .line 22
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    iget-object v0, v2, Lmb/s;->a:Lla/u;

    .line 26
    .line 27
    new-instance v1, Lif0/d;

    .line 28
    .line 29
    const/16 v4, 0x15

    .line 30
    .line 31
    invoke-direct {v1, v3, v4}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 32
    .line 33
    .line 34
    const/4 v4, 0x0

    .line 35
    const/4 v5, 0x1

    .line 36
    invoke-static {v0, v4, v5, v1}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 37
    .line 38
    .line 39
    move-result-object v0

    .line 40
    check-cast v0, Ljava/lang/Number;

    .line 41
    .line 42
    invoke-virtual {v0}, Ljava/lang/Number;->intValue()I

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lfb/f0;->a:Lmb/o;

    .line 46
    .line 47
    iget p0, p0, Lmb/o;->v:I

    .line 48
    .line 49
    invoke-virtual {v2, p0, v3}, Lmb/s;->h(ILjava/lang/String;)V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 53
    .line 54
    .line 55
    iget-object p0, v2, Lmb/s;->a:Lla/u;

    .line 56
    .line 57
    new-instance v0, Lif0/d;

    .line 58
    .line 59
    const/16 v1, 0x16

    .line 60
    .line 61
    invoke-direct {v0, v3, v1}, Lif0/d;-><init>(Ljava/lang/String;I)V

    .line 62
    .line 63
    .line 64
    invoke-static {p0, v4, v5, v0}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    const-wide/16 v0, -0x1

    .line 68
    .line 69
    invoke-virtual {v2, v0, v1, v3}, Lmb/s;->g(JLjava/lang/String;)I

    .line 70
    .line 71
    .line 72
    return-void
.end method

.method public final d(Leb/u;)V
    .locals 6

    .line 1
    const-string v0, "result"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lfb/f0;->c:Ljava/lang/String;

    .line 7
    .line 8
    filled-new-array {v0}, [Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v1

    .line 12
    invoke-static {v1}, Ljp/k1;->l([Ljava/lang/Object;)Ljava/util/ArrayList;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    :goto_0
    invoke-virtual {v1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 17
    .line 18
    .line 19
    move-result v2

    .line 20
    iget-object v3, p0, Lfb/f0;->i:Lmb/s;

    .line 21
    .line 22
    if-nez v2, :cond_1

    .line 23
    .line 24
    invoke-static {v1}, Lmx0/q;->e0(Ljava/util/List;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    move-result-object v2

    .line 28
    check-cast v2, Ljava/lang/String;

    .line 29
    .line 30
    invoke-virtual {v3, v2}, Lmb/s;->d(Ljava/lang/String;)Leb/h0;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    sget-object v5, Leb/h0;->i:Leb/h0;

    .line 35
    .line 36
    if-eq v4, v5, :cond_0

    .line 37
    .line 38
    sget-object v4, Leb/h0;->g:Leb/h0;

    .line 39
    .line 40
    invoke-virtual {v3, v4, v2}, Lmb/s;->j(Leb/h0;Ljava/lang/String;)I

    .line 41
    .line 42
    .line 43
    :cond_0
    iget-object v3, p0, Lfb/f0;->j:Lmb/b;

    .line 44
    .line 45
    invoke-virtual {v3, v2}, Lmb/b;->a(Ljava/lang/String;)Ljava/util/List;

    .line 46
    .line 47
    .line 48
    move-result-object v2

    .line 49
    check-cast v2, Ljava/util/Collection;

    .line 50
    .line 51
    invoke-virtual {v1, v2}, Ljava/util/ArrayList;->addAll(Ljava/util/Collection;)Z

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_1
    check-cast p1, Leb/r;

    .line 56
    .line 57
    iget-object p1, p1, Leb/r;->a:Leb/h;

    .line 58
    .line 59
    const-string v1, "getOutputData(...)"

    .line 60
    .line 61
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    iget-object p0, p0, Lfb/f0;->a:Lmb/o;

    .line 65
    .line 66
    iget p0, p0, Lmb/o;->v:I

    .line 67
    .line 68
    invoke-virtual {v3, p0, v0}, Lmb/s;->h(ILjava/lang/String;)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    iget-object p0, v3, Lmb/s;->a:Lla/u;

    .line 75
    .line 76
    new-instance v1, Ll2/v1;

    .line 77
    .line 78
    const/16 v2, 0xc

    .line 79
    .line 80
    invoke-direct {v1, v2, p1, v0}, Ll2/v1;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    const/4 p1, 0x0

    .line 84
    const/4 v0, 0x1

    .line 85
    invoke-static {p0, p1, v0, v1}, Ljp/ue;->f(Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    return-void
.end method
