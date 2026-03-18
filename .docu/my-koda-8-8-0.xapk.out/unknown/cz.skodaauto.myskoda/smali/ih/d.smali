.class public final Lih/d;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lai/e;

.field public final e:Lhh/c;

.field public final f:I

.field public final g:Lai/d;

.field public final h:Lyy0/c2;

.field public final i:Lyy0/l1;

.field public final j:Llx0/q;

.field public k:Lzg/h;


# direct methods
.method public constructor <init>(Lai/e;Lxh/e;Lzb/s0;Lag/c;Lag/c;Lhh/c;Lai/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lih/d;->d:Lai/e;

    .line 5
    .line 6
    iput-object p6, p0, Lih/d;->e:Lhh/c;

    .line 7
    .line 8
    const p1, 0x7fffffff

    .line 9
    .line 10
    .line 11
    iput p1, p0, Lih/d;->f:I

    .line 12
    .line 13
    iput-object p7, p0, Lih/d;->g:Lai/d;

    .line 14
    .line 15
    new-instance p1, Llc/q;

    .line 16
    .line 17
    sget-object p2, Llc/a;->c:Llc/c;

    .line 18
    .line 19
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    iput-object p1, p0, Lih/d;->h:Lyy0/c2;

    .line 27
    .line 28
    new-instance p2, Lyy0/l1;

    .line 29
    .line 30
    invoke-direct {p2, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 31
    .line 32
    .line 33
    iput-object p2, p0, Lih/d;->i:Lyy0/l1;

    .line 34
    .line 35
    invoke-static {p0}, Lzb/b;->F(Landroidx/lifecycle/b1;)Llx0/q;

    .line 36
    .line 37
    .line 38
    move-result-object p1

    .line 39
    iput-object p1, p0, Lih/d;->j:Llx0/q;

    .line 40
    .line 41
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 42
    .line 43
    .line 44
    move-result-object p1

    .line 45
    new-instance p2, Lih/c;

    .line 46
    .line 47
    const/4 p3, 0x0

    .line 48
    const/4 p4, 0x0

    .line 49
    invoke-direct {p2, p0, p4, p3}, Lih/c;-><init>(Lih/d;Lkotlin/coroutines/Continuation;I)V

    .line 50
    .line 51
    .line 52
    const/4 p0, 0x3

    .line 53
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 54
    .line 55
    .line 56
    return-void
.end method

.method public static final a(Lih/d;Lzg/h;)V
    .locals 40

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iput-object v1, v0, Lih/d;->k:Lzg/h;

    .line 6
    .line 7
    if-eqz v1, :cond_1a

    .line 8
    .line 9
    iget-object v2, v0, Lih/d;->h:Lyy0/c2;

    .line 10
    .line 11
    :goto_0
    invoke-virtual {v2}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v3

    .line 15
    move-object v4, v3

    .line 16
    check-cast v4, Llc/q;

    .line 17
    .line 18
    iget-object v4, v0, Lih/d;->g:Lai/d;

    .line 19
    .line 20
    const-string v5, "station"

    .line 21
    .line 22
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iget-object v5, v1, Lzg/h;->e:Lzg/g;

    .line 26
    .line 27
    iget-object v6, v1, Lzg/h;->g:Lzg/q;

    .line 28
    .line 29
    iget-object v7, v1, Lzg/h;->n:Ljava/lang/String;

    .line 30
    .line 31
    iget-object v8, v1, Lzg/h;->j:Ljava/lang/String;

    .line 32
    .line 33
    const-string v9, "downloadChargingStationImageUseCase"

    .line 34
    .line 35
    invoke-static {v4, v9}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    iget-object v9, v1, Lzg/h;->l:Ljava/lang/String;

    .line 39
    .line 40
    const/4 v10, 0x1

    .line 41
    const/4 v11, 0x0

    .line 42
    if-eqz v9, :cond_1

    .line 43
    .line 44
    invoke-virtual {v9}, Ljava/lang/String;->length()I

    .line 45
    .line 46
    .line 47
    move-result v12

    .line 48
    if-nez v12, :cond_0

    .line 49
    .line 50
    goto :goto_1

    .line 51
    :cond_0
    move v12, v11

    .line 52
    goto :goto_2

    .line 53
    :cond_1
    :goto_1
    move v12, v10

    .line 54
    :goto_2
    xor-int/lit8 v31, v12, 0x1

    .line 55
    .line 56
    if-eqz v9, :cond_2

    .line 57
    .line 58
    new-array v13, v10, [C

    .line 59
    .line 60
    const/16 v14, 0x2c

    .line 61
    .line 62
    aput-char v14, v13, v11

    .line 63
    .line 64
    invoke-static {v9, v13}, Lly0/p;->X(Ljava/lang/CharSequence;[C)Ljava/util/List;

    .line 65
    .line 66
    .line 67
    move-result-object v9

    .line 68
    goto :goto_3

    .line 69
    :cond_2
    const-string v9, "-"

    .line 70
    .line 71
    filled-new-array {v9, v9}, [Ljava/lang/String;

    .line 72
    .line 73
    .line 74
    move-result-object v9

    .line 75
    invoke-static {v9}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 76
    .line 77
    .line 78
    move-result-object v9

    .line 79
    :goto_3
    invoke-interface {v9, v11}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v13

    .line 83
    move-object/from16 v21, v13

    .line 84
    .line 85
    check-cast v21, Ljava/lang/String;

    .line 86
    .line 87
    invoke-interface {v9, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v9

    .line 91
    check-cast v9, Ljava/lang/String;

    .line 92
    .line 93
    invoke-static {v9}, Lly0/p;->l0(Ljava/lang/CharSequence;)Ljava/lang/CharSequence;

    .line 94
    .line 95
    .line 96
    move-result-object v9

    .line 97
    invoke-virtual {v9}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object v22

    .line 101
    if-eqz v8, :cond_4

    .line 102
    .line 103
    invoke-virtual {v8}, Ljava/lang/String;->length()I

    .line 104
    .line 105
    .line 106
    move-result v9

    .line 107
    if-nez v9, :cond_3

    .line 108
    .line 109
    goto :goto_4

    .line 110
    :cond_3
    move v9, v11

    .line 111
    goto :goto_5

    .line 112
    :cond_4
    :goto_4
    move v9, v10

    .line 113
    :goto_5
    xor-int/lit8 v32, v9, 0x1

    .line 114
    .line 115
    if-eqz v7, :cond_6

    .line 116
    .line 117
    invoke-virtual {v7}, Ljava/lang/String;->length()I

    .line 118
    .line 119
    .line 120
    move-result v13

    .line 121
    if-nez v13, :cond_5

    .line 122
    .line 123
    goto :goto_6

    .line 124
    :cond_5
    move v13, v11

    .line 125
    goto :goto_7

    .line 126
    :cond_6
    :goto_6
    move v13, v10

    .line 127
    :goto_7
    xor-int/lit8 v35, v13, 0x1

    .line 128
    .line 129
    if-eqz v6, :cond_7

    .line 130
    .line 131
    move/from16 v37, v10

    .line 132
    .line 133
    goto :goto_8

    .line 134
    :cond_7
    move/from16 v37, v11

    .line 135
    .line 136
    :goto_8
    iget-object v14, v1, Lzg/h;->i:Ljava/lang/String;

    .line 137
    .line 138
    iget-object v15, v1, Lzg/h;->f:Ljava/lang/String;

    .line 139
    .line 140
    iget-object v10, v1, Lzg/h;->h:Ljava/lang/String;

    .line 141
    .line 142
    iget-object v11, v1, Lzg/h;->p:Ljava/lang/Boolean;

    .line 143
    .line 144
    sget-object v0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 145
    .line 146
    invoke-static {v11, v0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 147
    .line 148
    .line 149
    move-result v0

    .line 150
    const-string v11, "<this>"

    .line 151
    .line 152
    invoke-static {v5, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 153
    .line 154
    .line 155
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 156
    .line 157
    .line 158
    move-result v11

    .line 159
    packed-switch v11, :pswitch_data_0

    .line 160
    .line 161
    .line 162
    new-instance v0, La8/r0;

    .line 163
    .line 164
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 165
    .line 166
    .line 167
    throw v0

    .line 168
    :pswitch_0
    sget-object v11, Lgh/a;->f:Lgh/a;

    .line 169
    .line 170
    :goto_9
    move-object/from16 v18, v11

    .line 171
    .line 172
    goto :goto_a

    .line 173
    :pswitch_1
    sget-object v11, Lgh/a;->h:Lgh/a;

    .line 174
    .line 175
    goto :goto_9

    .line 176
    :pswitch_2
    sget-object v11, Lgh/a;->g:Lgh/a;

    .line 177
    .line 178
    goto :goto_9

    .line 179
    :pswitch_3
    sget-object v11, Lgh/a;->e:Lgh/a;

    .line 180
    .line 181
    goto :goto_9

    .line 182
    :pswitch_4
    sget-object v11, Lgh/a;->d:Lgh/a;

    .line 183
    .line 184
    goto :goto_9

    .line 185
    :goto_a
    const-string v11, ""

    .line 186
    .line 187
    if-nez v8, :cond_8

    .line 188
    .line 189
    move-object/from16 v19, v11

    .line 190
    .line 191
    goto :goto_b

    .line 192
    :cond_8
    move-object/from16 v19, v8

    .line 193
    .line 194
    :goto_b
    iget-object v8, v1, Lzg/h;->k:Ljava/lang/String;

    .line 195
    .line 196
    if-nez v8, :cond_9

    .line 197
    .line 198
    move-object/from16 v20, v11

    .line 199
    .line 200
    :goto_c
    move/from16 v23, v0

    .line 201
    .line 202
    goto :goto_d

    .line 203
    :cond_9
    move-object/from16 v20, v8

    .line 204
    .line 205
    goto :goto_c

    .line 206
    :goto_d
    iget-object v0, v1, Lzg/h;->m:Ljava/lang/String;

    .line 207
    .line 208
    move/from16 v17, v23

    .line 209
    .line 210
    if-nez v0, :cond_a

    .line 211
    .line 212
    move-object/from16 v23, v11

    .line 213
    .line 214
    :goto_e
    const/16 v24, 0x0

    .line 215
    .line 216
    goto :goto_f

    .line 217
    :cond_a
    move-object/from16 v23, v0

    .line 218
    .line 219
    goto :goto_e

    .line 220
    :goto_f
    if-nez v7, :cond_b

    .line 221
    .line 222
    move-object v7, v11

    .line 223
    :cond_b
    move-object/from16 v25, v0

    .line 224
    .line 225
    sget-object v0, Lzg/g;->e:Lzg/g;

    .line 226
    .line 227
    move-object/from16 v26, v25

    .line 228
    .line 229
    if-ne v5, v0, :cond_c

    .line 230
    .line 231
    const/16 v25, 0x1

    .line 232
    .line 233
    goto :goto_10

    .line 234
    :cond_c
    move/from16 v25, v24

    .line 235
    .line 236
    :goto_10
    sget-object v0, Lzg/g;->g:Lzg/g;

    .line 237
    .line 238
    move-object/from16 v27, v26

    .line 239
    .line 240
    if-ne v5, v0, :cond_d

    .line 241
    .line 242
    const/16 v26, 0x1

    .line 243
    .line 244
    goto :goto_11

    .line 245
    :cond_d
    move/from16 v26, v24

    .line 246
    .line 247
    :goto_11
    sget-object v0, Lzg/g;->f:Lzg/g;

    .line 248
    .line 249
    move-object/from16 v28, v27

    .line 250
    .line 251
    if-ne v5, v0, :cond_e

    .line 252
    .line 253
    const/16 v27, 0x1

    .line 254
    .line 255
    goto :goto_12

    .line 256
    :cond_e
    move/from16 v27, v24

    .line 257
    .line 258
    :goto_12
    sget-object v0, Lzg/g;->i:Lzg/g;

    .line 259
    .line 260
    if-ne v5, v0, :cond_f

    .line 261
    .line 262
    move-object/from16 v0, v28

    .line 263
    .line 264
    const/16 v28, 0x1

    .line 265
    .line 266
    goto :goto_13

    .line 267
    :cond_f
    move-object/from16 v0, v28

    .line 268
    .line 269
    move/from16 v28, v24

    .line 270
    .line 271
    :goto_13
    if-eqz v6, :cond_10

    .line 272
    .line 273
    iget-object v5, v6, Lzg/q;->d:Ljava/lang/String;

    .line 274
    .line 275
    goto :goto_14

    .line 276
    :cond_10
    const/4 v5, 0x0

    .line 277
    :goto_14
    if-nez v5, :cond_11

    .line 278
    .line 279
    move-object v5, v11

    .line 280
    :cond_11
    if-eqz v6, :cond_12

    .line 281
    .line 282
    iget-object v6, v6, Lzg/q;->e:Ljava/lang/String;

    .line 283
    .line 284
    goto :goto_15

    .line 285
    :cond_12
    const/4 v6, 0x0

    .line 286
    :goto_15
    if-nez v6, :cond_13

    .line 287
    .line 288
    move-object/from16 v30, v11

    .line 289
    .line 290
    goto :goto_16

    .line 291
    :cond_13
    move-object/from16 v30, v6

    .line 292
    .line 293
    :goto_16
    if-eqz v0, :cond_14

    .line 294
    .line 295
    const/16 v34, 0x1

    .line 296
    .line 297
    goto :goto_17

    .line 298
    :cond_14
    move/from16 v34, v24

    .line 299
    .line 300
    :goto_17
    if-eqz v8, :cond_15

    .line 301
    .line 302
    const/16 v33, 0x1

    .line 303
    .line 304
    goto :goto_18

    .line 305
    :cond_15
    move/from16 v33, v24

    .line 306
    .line 307
    :goto_18
    if-eqz v12, :cond_17

    .line 308
    .line 309
    if-eqz v9, :cond_17

    .line 310
    .line 311
    if-nez v13, :cond_16

    .line 312
    .line 313
    goto :goto_19

    .line 314
    :cond_16
    move/from16 v36, v24

    .line 315
    .line 316
    goto :goto_1a

    .line 317
    :cond_17
    :goto_19
    const/16 v36, 0x1

    .line 318
    .line 319
    :goto_1a
    iget-boolean v0, v1, Lzg/h;->v:Z

    .line 320
    .line 321
    iget-object v6, v1, Lzg/h;->d:Ljava/util/List;

    .line 322
    .line 323
    check-cast v6, Ljava/lang/Iterable;

    .line 324
    .line 325
    new-instance v8, Ljava/util/ArrayList;

    .line 326
    .line 327
    const/16 v9, 0xa

    .line 328
    .line 329
    invoke-static {v6, v9}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 330
    .line 331
    .line 332
    move-result v9

    .line 333
    invoke-direct {v8, v9}, Ljava/util/ArrayList;-><init>(I)V

    .line 334
    .line 335
    .line 336
    invoke-interface {v6}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 337
    .line 338
    .line 339
    move-result-object v6

    .line 340
    :goto_1b
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 341
    .line 342
    .line 343
    move-result v9

    .line 344
    if-eqz v9, :cond_18

    .line 345
    .line 346
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object v9

    .line 350
    check-cast v9, Ljava/lang/String;

    .line 351
    .line 352
    invoke-virtual {v4, v9}, Lai/d;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 353
    .line 354
    .line 355
    move-result-object v9

    .line 356
    check-cast v9, Lkc/e;

    .line 357
    .line 358
    invoke-virtual {v8, v9}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 359
    .line 360
    .line 361
    goto :goto_1b

    .line 362
    :cond_18
    new-instance v13, Lih/a;

    .line 363
    .line 364
    move/from16 v38, v0

    .line 365
    .line 366
    move-object/from16 v29, v5

    .line 367
    .line 368
    move-object/from16 v24, v7

    .line 369
    .line 370
    move-object/from16 v39, v8

    .line 371
    .line 372
    move-object/from16 v16, v10

    .line 373
    .line 374
    invoke-direct/range {v13 .. v39}, Lih/a;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZLgh/a;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZLjava/lang/String;Ljava/lang/String;ZZZZZZZZLjava/util/ArrayList;)V

    .line 375
    .line 376
    .line 377
    new-instance v0, Llc/q;

    .line 378
    .line 379
    invoke-direct {v0, v13}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 380
    .line 381
    .line 382
    invoke-virtual {v2, v3, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 383
    .line 384
    .line 385
    move-result v0

    .line 386
    if-eqz v0, :cond_19

    .line 387
    .line 388
    goto :goto_1c

    .line 389
    :cond_19
    move-object/from16 v0, p0

    .line 390
    .line 391
    goto/16 :goto_0

    .line 392
    .line 393
    :cond_1a
    :goto_1c
    return-void

    .line 394
    nop

    .line 395
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_2
        :pswitch_3
        :pswitch_1
        :pswitch_0
        :pswitch_4
        :pswitch_3
    .end packed-switch
.end method
