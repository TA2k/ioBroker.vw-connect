.class public final Lpi/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final g:[Ljava/lang/Integer;


# instance fields
.field public final a:Lvy0/b0;

.field public final b:Lr1/b;

.field public final c:Ljd/b;

.field public final d:Ljd/b;

.field public final e:Ll20/c;

.field public final f:Ljava/util/LinkedHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 19

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 3
    .line 4
    .line 5
    move-result-object v1

    .line 6
    const/4 v0, 0x2

    .line 7
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 8
    .line 9
    .line 10
    move-result-object v3

    .line 11
    const/4 v0, 0x3

    .line 12
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 13
    .line 14
    .line 15
    move-result-object v4

    .line 16
    const/4 v0, 0x5

    .line 17
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 18
    .line 19
    .line 20
    move-result-object v5

    .line 21
    const/16 v0, 0x8

    .line 22
    .line 23
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object v6

    .line 27
    const/16 v0, 0xd

    .line 28
    .line 29
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 30
    .line 31
    .line 32
    move-result-object v7

    .line 33
    const/16 v0, 0x15

    .line 34
    .line 35
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 36
    .line 37
    .line 38
    move-result-object v8

    .line 39
    const/16 v0, 0x22

    .line 40
    .line 41
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 42
    .line 43
    .line 44
    move-result-object v9

    .line 45
    const/16 v0, 0x37

    .line 46
    .line 47
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 48
    .line 49
    .line 50
    move-result-object v10

    .line 51
    const/16 v0, 0x59

    .line 52
    .line 53
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 54
    .line 55
    .line 56
    move-result-object v11

    .line 57
    move-object v2, v1

    .line 58
    move-object v12, v11

    .line 59
    move-object v13, v11

    .line 60
    move-object v14, v11

    .line 61
    move-object v15, v11

    .line 62
    move-object/from16 v16, v11

    .line 63
    .line 64
    move-object/from16 v17, v11

    .line 65
    .line 66
    move-object/from16 v18, v11

    .line 67
    .line 68
    filled-new-array/range {v1 .. v18}, [Ljava/lang/Integer;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    sput-object v0, Lpi/b;->g:[Ljava/lang/Integer;

    .line 73
    .line 74
    return-void
.end method

.method public constructor <init>(Lvy0/b0;Lr1/b;Ljd/b;Ljd/b;Ll20/c;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpi/b;->a:Lvy0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lpi/b;->b:Lr1/b;

    .line 7
    .line 8
    iput-object p3, p0, Lpi/b;->c:Ljd/b;

    .line 9
    .line 10
    iput-object p4, p0, Lpi/b;->d:Ljd/b;

    .line 11
    .line 12
    iput-object p5, p0, Lpi/b;->e:Ll20/c;

    .line 13
    .line 14
    new-instance p1, Ljava/util/LinkedHashMap;

    .line 15
    .line 16
    invoke-direct {p1}, Ljava/util/LinkedHashMap;-><init>()V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lpi/b;->f:Ljava/util/LinkedHashMap;

    .line 20
    .line 21
    return-void
.end method

.method public static final a(Lpi/b;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    instance-of v2, v1, Lpi/a;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lpi/a;

    .line 11
    .line 12
    iget v3, v2, Lpi/a;->o:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lpi/a;->o:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lpi/a;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lpi/a;-><init>(Lpi/b;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lpi/a;->m:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lpi/a;->o:I

    .line 34
    .line 35
    const-string v5, "Kt"

    .line 36
    .line 37
    const-class v8, Lpi/b;

    .line 38
    .line 39
    const/4 v9, 0x1

    .line 40
    const/4 v10, 0x0

    .line 41
    const/4 v11, 0x2

    .line 42
    const/4 v12, 0x0

    .line 43
    if-eqz v4, :cond_3

    .line 44
    .line 45
    if-eq v4, v9, :cond_2

    .line 46
    .line 47
    if-ne v4, v11, :cond_1

    .line 48
    .line 49
    iget v4, v2, Lpi/a;->j:I

    .line 50
    .line 51
    iget v13, v2, Lpi/a;->i:I

    .line 52
    .line 53
    iget v14, v2, Lpi/a;->h:I

    .line 54
    .line 55
    iget-object v15, v2, Lpi/a;->f:[Ljava/lang/Integer;

    .line 56
    .line 57
    iget-object v11, v2, Lpi/a;->e:Lkotlin/jvm/internal/f0;

    .line 58
    .line 59
    iget-object v6, v2, Lpi/a;->d:Ljava/lang/String;

    .line 60
    .line 61
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    move v0, v4

    .line 65
    move-object/from16 v17, v8

    .line 66
    .line 67
    const/4 v1, 0x2

    .line 68
    move-object v4, v3

    .line 69
    goto/16 :goto_6

    .line 70
    .line 71
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 72
    .line 73
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 74
    .line 75
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    throw v0

    .line 79
    :cond_2
    iget v4, v2, Lpi/a;->l:I

    .line 80
    .line 81
    iget v6, v2, Lpi/a;->k:I

    .line 82
    .line 83
    iget v11, v2, Lpi/a;->j:I

    .line 84
    .line 85
    iget v13, v2, Lpi/a;->i:I

    .line 86
    .line 87
    iget v14, v2, Lpi/a;->h:I

    .line 88
    .line 89
    iget-object v15, v2, Lpi/a;->f:[Ljava/lang/Integer;

    .line 90
    .line 91
    iget-object v7, v2, Lpi/a;->e:Lkotlin/jvm/internal/f0;

    .line 92
    .line 93
    iget-object v9, v2, Lpi/a;->d:Ljava/lang/String;

    .line 94
    .line 95
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 96
    .line 97
    .line 98
    move/from16 v20, v6

    .line 99
    .line 100
    move v6, v4

    .line 101
    move v4, v11

    .line 102
    move-object v11, v7

    .line 103
    move v7, v13

    .line 104
    move/from16 v13, v20

    .line 105
    .line 106
    goto :goto_2

    .line 107
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    new-instance v1, Lkotlin/jvm/internal/f0;

    .line 111
    .line 112
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 113
    .line 114
    .line 115
    sget-object v4, Lpi/b;->g:[Ljava/lang/Integer;

    .line 116
    .line 117
    const/16 v6, 0x12

    .line 118
    .line 119
    move v7, v6

    .line 120
    move v9, v10

    .line 121
    move v11, v9

    .line 122
    move-object v6, v4

    .line 123
    move-object v4, v2

    .line 124
    move-object v2, v1

    .line 125
    move-object/from16 v1, p1

    .line 126
    .line 127
    :goto_1
    if-ge v9, v7, :cond_a

    .line 128
    .line 129
    aget-object v13, v6, v9

    .line 130
    .line 131
    invoke-virtual {v13}, Ljava/lang/Number;->intValue()I

    .line 132
    .line 133
    .line 134
    move-result v13

    .line 135
    iget-object v14, v0, Lpi/b;->c:Ljd/b;

    .line 136
    .line 137
    iput-object v1, v4, Lpi/a;->d:Ljava/lang/String;

    .line 138
    .line 139
    iput-object v2, v4, Lpi/a;->e:Lkotlin/jvm/internal/f0;

    .line 140
    .line 141
    iput-object v6, v4, Lpi/a;->f:[Ljava/lang/Integer;

    .line 142
    .line 143
    iput-object v12, v4, Lpi/a;->g:Ljava/lang/Object;

    .line 144
    .line 145
    iput v11, v4, Lpi/a;->h:I

    .line 146
    .line 147
    iput v9, v4, Lpi/a;->i:I

    .line 148
    .line 149
    iput v7, v4, Lpi/a;->j:I

    .line 150
    .line 151
    iput v13, v4, Lpi/a;->k:I

    .line 152
    .line 153
    iput v10, v4, Lpi/a;->l:I

    .line 154
    .line 155
    const/4 v15, 0x1

    .line 156
    iput v15, v4, Lpi/a;->o:I

    .line 157
    .line 158
    invoke-virtual {v14, v1, v4}, Ljd/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object v14

    .line 162
    if-ne v14, v3, :cond_4

    .line 163
    .line 164
    move-object v4, v3

    .line 165
    goto/16 :goto_5

    .line 166
    .line 167
    :cond_4
    move v15, v9

    .line 168
    move-object v9, v1

    .line 169
    move-object v1, v14

    .line 170
    move v14, v11

    .line 171
    move-object v11, v2

    .line 172
    move-object v2, v4

    .line 173
    move v4, v7

    .line 174
    move v7, v15

    .line 175
    move-object v15, v6

    .line 176
    move v6, v10

    .line 177
    :goto_2
    check-cast v1, Llx0/o;

    .line 178
    .line 179
    iget-object v1, v1, Llx0/o;->d:Ljava/lang/Object;

    .line 180
    .line 181
    instance-of v10, v1, Llx0/n;

    .line 182
    .line 183
    if-nez v10, :cond_6

    .line 184
    .line 185
    check-cast v1, Lmi/c;

    .line 186
    .line 187
    new-instance v0, Lod0/d;

    .line 188
    .line 189
    const/4 v2, 0x6

    .line 190
    invoke-direct {v0, v9, v2}, Lod0/d;-><init>(Ljava/lang/String;I)V

    .line 191
    .line 192
    .line 193
    sget-object v2, Lgi/b;->e:Lgi/b;

    .line 194
    .line 195
    sget-object v3, Lgi/a;->e:Lgi/a;

    .line 196
    .line 197
    invoke-virtual {v8}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 198
    .line 199
    .line 200
    move-result-object v4

    .line 201
    const/16 v6, 0x24

    .line 202
    .line 203
    invoke-static {v4, v6}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 204
    .line 205
    .line 206
    move-result-object v6

    .line 207
    const/16 v7, 0x2e

    .line 208
    .line 209
    invoke-static {v7, v6, v6}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 210
    .line 211
    .line 212
    move-result-object v6

    .line 213
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 214
    .line 215
    .line 216
    move-result v7

    .line 217
    if-nez v7, :cond_5

    .line 218
    .line 219
    goto :goto_3

    .line 220
    :cond_5
    invoke-static {v6, v5}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 221
    .line 222
    .line 223
    move-result-object v4

    .line 224
    :goto_3
    invoke-static {v4, v3, v2, v12, v0}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 225
    .line 226
    .line 227
    return-object v1

    .line 228
    :cond_6
    invoke-static {v1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 229
    .line 230
    .line 231
    move-result-object v10

    .line 232
    if-eqz v10, :cond_9

    .line 233
    .line 234
    iput-object v10, v11, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 235
    .line 236
    sget-object v12, Lgi/b;->h:Lgi/b;

    .line 237
    .line 238
    new-instance v0, Ldg/c;

    .line 239
    .line 240
    move-object/from16 v17, v8

    .line 241
    .line 242
    const/4 v8, 0x1

    .line 243
    invoke-direct {v0, v10, v8}, Ldg/c;-><init>(Ljava/lang/Throwable;I)V

    .line 244
    .line 245
    .line 246
    sget-object v8, Lgi/a;->e:Lgi/a;

    .line 247
    .line 248
    move-object/from16 v18, v3

    .line 249
    .line 250
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 251
    .line 252
    .line 253
    move-result-object v3

    .line 254
    move/from16 v19, v4

    .line 255
    .line 256
    move/from16 p1, v6

    .line 257
    .line 258
    const/16 v6, 0x24

    .line 259
    .line 260
    invoke-static {v3, v6}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 261
    .line 262
    .line 263
    move-result-object v4

    .line 264
    const/16 v6, 0x2e

    .line 265
    .line 266
    invoke-static {v6, v4, v4}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v4

    .line 270
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 271
    .line 272
    .line 273
    move-result v6

    .line 274
    if-nez v6, :cond_7

    .line 275
    .line 276
    goto :goto_4

    .line 277
    :cond_7
    invoke-static {v4, v5}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 278
    .line 279
    .line 280
    move-result-object v3

    .line 281
    :goto_4
    invoke-static {v3, v8, v12, v10, v0}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 282
    .line 283
    .line 284
    sget v0, Lmy0/c;->g:I

    .line 285
    .line 286
    sget-object v0, Lmy0/e;->h:Lmy0/e;

    .line 287
    .line 288
    invoke-static {v13, v0}, Lmy0/h;->s(ILmy0/e;)J

    .line 289
    .line 290
    .line 291
    move-result-wide v3

    .line 292
    iput-object v9, v2, Lpi/a;->d:Ljava/lang/String;

    .line 293
    .line 294
    iput-object v11, v2, Lpi/a;->e:Lkotlin/jvm/internal/f0;

    .line 295
    .line 296
    iput-object v15, v2, Lpi/a;->f:[Ljava/lang/Integer;

    .line 297
    .line 298
    iput-object v1, v2, Lpi/a;->g:Ljava/lang/Object;

    .line 299
    .line 300
    iput v14, v2, Lpi/a;->h:I

    .line 301
    .line 302
    iput v7, v2, Lpi/a;->i:I

    .line 303
    .line 304
    move/from16 v0, v19

    .line 305
    .line 306
    iput v0, v2, Lpi/a;->j:I

    .line 307
    .line 308
    iput v13, v2, Lpi/a;->k:I

    .line 309
    .line 310
    move/from16 v10, p1

    .line 311
    .line 312
    iput v10, v2, Lpi/a;->l:I

    .line 313
    .line 314
    const/4 v1, 0x2

    .line 315
    iput v1, v2, Lpi/a;->o:I

    .line 316
    .line 317
    invoke-static {v3, v4, v2}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 318
    .line 319
    .line 320
    move-result-object v3

    .line 321
    move-object/from16 v4, v18

    .line 322
    .line 323
    if-ne v3, v4, :cond_8

    .line 324
    .line 325
    :goto_5
    return-object v4

    .line 326
    :cond_8
    move v13, v7

    .line 327
    move-object v6, v9

    .line 328
    :goto_6
    move v7, v13

    .line 329
    :goto_7
    move v3, v0

    .line 330
    move-object v0, v2

    .line 331
    move-object v2, v11

    .line 332
    move v11, v14

    .line 333
    const/16 v16, 0x1

    .line 334
    .line 335
    goto :goto_8

    .line 336
    :cond_9
    move v0, v4

    .line 337
    move-object/from16 v17, v8

    .line 338
    .line 339
    const/4 v1, 0x2

    .line 340
    move-object v4, v3

    .line 341
    move-object v6, v9

    .line 342
    goto :goto_7

    .line 343
    :goto_8
    add-int/lit8 v9, v7, 0x1

    .line 344
    .line 345
    move v7, v3

    .line 346
    move-object v3, v4

    .line 347
    move-object v1, v6

    .line 348
    move-object v6, v15

    .line 349
    move-object/from16 v8, v17

    .line 350
    .line 351
    const/4 v10, 0x0

    .line 352
    const/4 v12, 0x0

    .line 353
    move-object v4, v0

    .line 354
    move-object/from16 v0, p0

    .line 355
    .line 356
    goto/16 :goto_1

    .line 357
    .line 358
    :cond_a
    move-object/from16 v17, v8

    .line 359
    .line 360
    sget-object v0, Lgi/b;->h:Lgi/b;

    .line 361
    .line 362
    new-instance v1, Lp81/c;

    .line 363
    .line 364
    const/16 v2, 0xb

    .line 365
    .line 366
    invoke-direct {v1, v2}, Lp81/c;-><init>(I)V

    .line 367
    .line 368
    .line 369
    sget-object v2, Lgi/a;->e:Lgi/a;

    .line 370
    .line 371
    invoke-virtual/range {v17 .. v17}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 372
    .line 373
    .line 374
    move-result-object v3

    .line 375
    const/16 v6, 0x24

    .line 376
    .line 377
    invoke-static {v3, v6}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 378
    .line 379
    .line 380
    move-result-object v4

    .line 381
    const/16 v6, 0x2e

    .line 382
    .line 383
    invoke-static {v6, v4, v4}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 384
    .line 385
    .line 386
    move-result-object v4

    .line 387
    invoke-virtual {v4}, Ljava/lang/String;->length()I

    .line 388
    .line 389
    .line 390
    move-result v6

    .line 391
    if-nez v6, :cond_b

    .line 392
    .line 393
    :goto_9
    const/4 v4, 0x0

    .line 394
    goto :goto_a

    .line 395
    :cond_b
    invoke-static {v4, v5}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 396
    .line 397
    .line 398
    move-result-object v3

    .line 399
    goto :goto_9

    .line 400
    :goto_a
    invoke-static {v3, v2, v0, v4, v1}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 401
    .line 402
    .line 403
    return-object v4
.end method
