.class public final Lg1/t1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public d:Lkotlin/jvm/internal/b0;

.field public e:Lkotlin/jvm/internal/b0;

.field public f:I

.field public g:I

.field public synthetic h:Ljava/lang/Object;

.field public final synthetic i:Lkotlin/jvm/internal/c0;

.field public final synthetic j:Lkotlin/jvm/internal/f0;

.field public final synthetic k:Lkotlin/jvm/internal/f0;

.field public final synthetic l:F

.field public final synthetic m:Lb0/d1;

.field public final synthetic n:F

.field public final synthetic o:Lg1/u2;


# direct methods
.method public constructor <init>(Lkotlin/jvm/internal/c0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;FLb0/d1;FLg1/u2;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lg1/t1;->i:Lkotlin/jvm/internal/c0;

    .line 2
    .line 3
    iput-object p2, p0, Lg1/t1;->j:Lkotlin/jvm/internal/f0;

    .line 4
    .line 5
    iput-object p3, p0, Lg1/t1;->k:Lkotlin/jvm/internal/f0;

    .line 6
    .line 7
    iput p4, p0, Lg1/t1;->l:F

    .line 8
    .line 9
    iput-object p5, p0, Lg1/t1;->m:Lb0/d1;

    .line 10
    .line 11
    iput p6, p0, Lg1/t1;->n:F

    .line 12
    .line 13
    iput-object p7, p0, Lg1/t1;->o:Lg1/u2;

    .line 14
    .line 15
    const/4 p1, 0x2

    .line 16
    invoke-direct {p0, p1, p8}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 17
    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 9

    .line 1
    new-instance v0, Lg1/t1;

    .line 2
    .line 3
    iget v6, p0, Lg1/t1;->n:F

    .line 4
    .line 5
    iget-object v7, p0, Lg1/t1;->o:Lg1/u2;

    .line 6
    .line 7
    iget-object v1, p0, Lg1/t1;->i:Lkotlin/jvm/internal/c0;

    .line 8
    .line 9
    iget-object v2, p0, Lg1/t1;->j:Lkotlin/jvm/internal/f0;

    .line 10
    .line 11
    iget-object v3, p0, Lg1/t1;->k:Lkotlin/jvm/internal/f0;

    .line 12
    .line 13
    iget v4, p0, Lg1/t1;->l:F

    .line 14
    .line 15
    iget-object v5, p0, Lg1/t1;->m:Lb0/d1;

    .line 16
    .line 17
    move-object v8, p2

    .line 18
    invoke-direct/range {v0 .. v8}, Lg1/t1;-><init>(Lkotlin/jvm/internal/c0;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/f0;FLb0/d1;FLg1/u2;Lkotlin/coroutines/Continuation;)V

    .line 19
    .line 20
    .line 21
    iput-object p1, v0, Lg1/t1;->h:Ljava/lang/Object;

    .line 22
    .line 23
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lg1/t2;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lg1/t1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lg1/t1;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lg1/t1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 21

    .line 1
    move-object/from16 v7, p0

    .line 2
    .line 3
    sget-object v8, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v0, v7, Lg1/t1;->g:I

    .line 6
    .line 7
    iget-object v1, v7, Lg1/t1;->k:Lkotlin/jvm/internal/f0;

    .line 8
    .line 9
    iget-object v2, v7, Lg1/t1;->i:Lkotlin/jvm/internal/c0;

    .line 10
    .line 11
    const/4 v6, 0x3

    .line 12
    const/4 v3, 0x2

    .line 13
    const/4 v4, 0x1

    .line 14
    iget-object v5, v7, Lg1/t1;->j:Lkotlin/jvm/internal/f0;

    .line 15
    .line 16
    if-eqz v0, :cond_3

    .line 17
    .line 18
    if-eq v0, v4, :cond_2

    .line 19
    .line 20
    if-eq v0, v3, :cond_1

    .line 21
    .line 22
    if-ne v0, v6, :cond_0

    .line 23
    .line 24
    iget-object v0, v7, Lg1/t1;->e:Lkotlin/jvm/internal/b0;

    .line 25
    .line 26
    iget-object v9, v7, Lg1/t1;->d:Lkotlin/jvm/internal/b0;

    .line 27
    .line 28
    iget-object v10, v7, Lg1/t1;->h:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v10, Lg1/t2;

    .line 31
    .line 32
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    move v11, v3

    .line 36
    move v14, v4

    .line 37
    move-object v4, v5

    .line 38
    move/from16 v18, v6

    .line 39
    .line 40
    move-object v3, v9

    .line 41
    move-object v9, v0

    .line 42
    move-object/from16 v0, p1

    .line 43
    .line 44
    goto/16 :goto_4

    .line 45
    .line 46
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw v0

    .line 54
    :cond_1
    iget v0, v7, Lg1/t1;->f:I

    .line 55
    .line 56
    iget-object v9, v7, Lg1/t1;->d:Lkotlin/jvm/internal/b0;

    .line 57
    .line 58
    iget-object v10, v7, Lg1/t1;->h:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v10, Lg1/t2;

    .line 61
    .line 62
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    move-object/from16 v19, v1

    .line 66
    .line 67
    move-object/from16 v20, v2

    .line 68
    .line 69
    move v11, v3

    .line 70
    move v14, v4

    .line 71
    move-object v6, v5

    .line 72
    goto/16 :goto_3

    .line 73
    .line 74
    :cond_2
    iget-object v0, v7, Lg1/t1;->e:Lkotlin/jvm/internal/b0;

    .line 75
    .line 76
    iget-object v9, v7, Lg1/t1;->d:Lkotlin/jvm/internal/b0;

    .line 77
    .line 78
    iget-object v10, v7, Lg1/t1;->h:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v10, Lg1/t2;

    .line 81
    .line 82
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    move v11, v3

    .line 86
    move v14, v4

    .line 87
    move-object v4, v5

    .line 88
    move/from16 v18, v6

    .line 89
    .line 90
    move-object v3, v9

    .line 91
    move-object v9, v0

    .line 92
    move-object/from16 v0, p1

    .line 93
    .line 94
    goto/16 :goto_8

    .line 95
    .line 96
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    iget-object v0, v7, Lg1/t1;->h:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v0, Lg1/t2;

    .line 102
    .line 103
    new-instance v9, Lkotlin/jvm/internal/b0;

    .line 104
    .line 105
    invoke-direct {v9}, Ljava/lang/Object;-><init>()V

    .line 106
    .line 107
    .line 108
    iput-boolean v4, v9, Lkotlin/jvm/internal/b0;->d:Z

    .line 109
    .line 110
    :goto_0
    move-object v14, v9

    .line 111
    :goto_1
    iget-boolean v9, v14, Lkotlin/jvm/internal/b0;->d:Z

    .line 112
    .line 113
    sget-object v16, Llx0/b0;->a:Llx0/b0;

    .line 114
    .line 115
    if-eqz v9, :cond_c

    .line 116
    .line 117
    const/4 v9, 0x0

    .line 118
    iput-boolean v9, v14, Lkotlin/jvm/internal/b0;->d:Z

    .line 119
    .line 120
    iget v10, v2, Lkotlin/jvm/internal/c0;->d:F

    .line 121
    .line 122
    iget-object v11, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 123
    .line 124
    check-cast v11, Lc1/k;

    .line 125
    .line 126
    iget-object v11, v11, Lc1/k;->e:Ll2/j1;

    .line 127
    .line 128
    invoke-virtual {v11}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object v11

    .line 132
    check-cast v11, Ljava/lang/Number;

    .line 133
    .line 134
    invoke-virtual {v11}, Ljava/lang/Number;->floatValue()F

    .line 135
    .line 136
    .line 137
    move-result v11

    .line 138
    sub-float/2addr v10, v11

    .line 139
    iget-object v11, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 140
    .line 141
    check-cast v11, Lg1/r1;

    .line 142
    .line 143
    iget-boolean v11, v11, Lg1/r1;->c:Z

    .line 144
    .line 145
    iget-object v12, v7, Lg1/t1;->m:Lb0/d1;

    .line 146
    .line 147
    if-nez v11, :cond_4

    .line 148
    .line 149
    invoke-static {v10}, Ljava/lang/Math;->abs(F)F

    .line 150
    .line 151
    .line 152
    move-result v11

    .line 153
    iget v13, v7, Lg1/t1;->l:F

    .line 154
    .line 155
    cmpg-float v11, v11, v13

    .line 156
    .line 157
    if-gez v11, :cond_5

    .line 158
    .line 159
    :cond_4
    move-object v13, v0

    .line 160
    move v11, v3

    .line 161
    move/from16 v18, v6

    .line 162
    .line 163
    move-object v9, v14

    .line 164
    move v14, v4

    .line 165
    move-object v4, v5

    .line 166
    goto/16 :goto_6

    .line 167
    .line 168
    :cond_5
    invoke-static {v10}, Ljava/lang/Math;->signum(F)F

    .line 169
    .line 170
    .line 171
    move-result v10

    .line 172
    mul-float/2addr v10, v13

    .line 173
    invoke-virtual {v12, v0, v10}, Lb0/d1;->c(Lg1/t2;F)F

    .line 174
    .line 175
    .line 176
    iget-object v11, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 177
    .line 178
    check-cast v11, Lc1/k;

    .line 179
    .line 180
    iget-object v12, v11, Lc1/k;->e:Ll2/j1;

    .line 181
    .line 182
    invoke-virtual {v12}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v12

    .line 186
    check-cast v12, Ljava/lang/Number;

    .line 187
    .line 188
    invoke-virtual {v12}, Ljava/lang/Number;->floatValue()F

    .line 189
    .line 190
    .line 191
    move-result v12

    .line 192
    add-float/2addr v12, v10

    .line 193
    const/4 v10, 0x0

    .line 194
    const/16 v13, 0x1e

    .line 195
    .line 196
    invoke-static {v11, v12, v10, v13}, Lc1/d;->m(Lc1/k;FFI)Lc1/k;

    .line 197
    .line 198
    .line 199
    move-result-object v10

    .line 200
    iput-object v10, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 201
    .line 202
    iget v11, v2, Lkotlin/jvm/internal/c0;->d:F

    .line 203
    .line 204
    iget-object v10, v10, Lc1/k;->e:Ll2/j1;

    .line 205
    .line 206
    invoke-virtual {v10}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 207
    .line 208
    .line 209
    move-result-object v10

    .line 210
    check-cast v10, Ljava/lang/Number;

    .line 211
    .line 212
    invoke-virtual {v10}, Ljava/lang/Number;->floatValue()F

    .line 213
    .line 214
    .line 215
    move-result v10

    .line 216
    sub-float/2addr v11, v10

    .line 217
    invoke-static {v11}, Ljava/lang/Math;->abs(F)F

    .line 218
    .line 219
    .line 220
    move-result v10

    .line 221
    iget v11, v7, Lg1/t1;->n:F

    .line 222
    .line 223
    div-float/2addr v10, v11

    .line 224
    invoke-static {v10}, Lcy0/a;->i(F)I

    .line 225
    .line 226
    .line 227
    move-result v10

    .line 228
    const/16 v11, 0x64

    .line 229
    .line 230
    if-le v10, v11, :cond_6

    .line 231
    .line 232
    move v10, v11

    .line 233
    :cond_6
    iget-object v11, v5, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 234
    .line 235
    check-cast v11, Lc1/k;

    .line 236
    .line 237
    iget v12, v2, Lkotlin/jvm/internal/c0;->d:F

    .line 238
    .line 239
    move v13, v9

    .line 240
    new-instance v9, Lc/b;

    .line 241
    .line 242
    const/4 v15, 0x3

    .line 243
    move/from16 v17, v10

    .line 244
    .line 245
    iget-object v10, v7, Lg1/t1;->m:Lb0/d1;

    .line 246
    .line 247
    move/from16 v18, v13

    .line 248
    .line 249
    iget-object v13, v7, Lg1/t1;->o:Lg1/u2;

    .line 250
    .line 251
    move v4, v12

    .line 252
    move/from16 v6, v18

    .line 253
    .line 254
    move-object v12, v2

    .line 255
    move-object v2, v11

    .line 256
    move-object v11, v1

    .line 257
    move/from16 v1, v17

    .line 258
    .line 259
    invoke-direct/range {v9 .. v15}, Lc/b;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 260
    .line 261
    .line 262
    move-object/from16 v19, v14

    .line 263
    .line 264
    move-object v14, v9

    .line 265
    move-object/from16 v9, v19

    .line 266
    .line 267
    move-object/from16 v19, v11

    .line 268
    .line 269
    move-object/from16 v20, v12

    .line 270
    .line 271
    iput-object v0, v7, Lg1/t1;->h:Ljava/lang/Object;

    .line 272
    .line 273
    iput-object v9, v7, Lg1/t1;->d:Lkotlin/jvm/internal/b0;

    .line 274
    .line 275
    const/4 v11, 0x0

    .line 276
    iput-object v11, v7, Lg1/t1;->e:Lkotlin/jvm/internal/b0;

    .line 277
    .line 278
    iput v1, v7, Lg1/t1;->f:I

    .line 279
    .line 280
    iput v3, v7, Lg1/t1;->g:I

    .line 281
    .line 282
    invoke-virtual {v10}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 283
    .line 284
    .line 285
    new-instance v11, Lkotlin/jvm/internal/c0;

    .line 286
    .line 287
    invoke-direct {v11}, Ljava/lang/Object;-><init>()V

    .line 288
    .line 289
    .line 290
    iget-object v12, v2, Lc1/k;->e:Ll2/j1;

    .line 291
    .line 292
    invoke-virtual {v12}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 293
    .line 294
    .line 295
    move-result-object v12

    .line 296
    check-cast v12, Ljava/lang/Number;

    .line 297
    .line 298
    invoke-virtual {v12}, Ljava/lang/Number;->floatValue()F

    .line 299
    .line 300
    .line 301
    move-result v12

    .line 302
    iput v12, v11, Lkotlin/jvm/internal/c0;->d:F

    .line 303
    .line 304
    new-instance v12, Ljava/lang/Float;

    .line 305
    .line 306
    invoke-direct {v12, v4}, Ljava/lang/Float;-><init>(F)V

    .line 307
    .line 308
    .line 309
    sget-object v4, Lc1/z;->d:Lc1/y;

    .line 310
    .line 311
    invoke-static {v1, v6, v4, v3}, Lc1/d;->u(IILc1/w;I)Lc1/a2;

    .line 312
    .line 313
    .line 314
    move-result-object v4

    .line 315
    move-object v6, v12

    .line 316
    move-object v12, v10

    .line 317
    new-instance v10, Lbg/a;

    .line 318
    .line 319
    const/16 v15, 0x8

    .line 320
    .line 321
    move-object v13, v0

    .line 322
    invoke-direct/range {v10 .. v15}, Lbg/a;-><init>(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 323
    .line 324
    .line 325
    move v0, v3

    .line 326
    const/4 v3, 0x1

    .line 327
    move v11, v0

    .line 328
    move-object v0, v2

    .line 329
    move-object v2, v4

    .line 330
    move-object v1, v6

    .line 331
    move-object v4, v10

    .line 332
    const/4 v14, 0x1

    .line 333
    move-object v6, v5

    .line 334
    move-object v5, v7

    .line 335
    invoke-static/range {v0 .. v5}, Lc1/d;->h(Lc1/k;Ljava/lang/Float;Lc1/j;ZLay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 336
    .line 337
    .line 338
    move-result-object v0

    .line 339
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 340
    .line 341
    if-ne v0, v1, :cond_7

    .line 342
    .line 343
    goto :goto_2

    .line 344
    :cond_7
    move-object/from16 v0, v16

    .line 345
    .line 346
    :goto_2
    if-ne v0, v8, :cond_8

    .line 347
    .line 348
    goto/16 :goto_7

    .line 349
    .line 350
    :cond_8
    move-object v10, v13

    .line 351
    move/from16 v0, v17

    .line 352
    .line 353
    :goto_3
    iget-boolean v1, v9, Lkotlin/jvm/internal/b0;->d:Z

    .line 354
    .line 355
    if-nez v1, :cond_a

    .line 356
    .line 357
    const-wide/16 v1, 0x32

    .line 358
    .line 359
    int-to-long v3, v0

    .line 360
    sub-long/2addr v1, v3

    .line 361
    iput-object v10, v7, Lg1/t1;->h:Ljava/lang/Object;

    .line 362
    .line 363
    iput-object v9, v7, Lg1/t1;->d:Lkotlin/jvm/internal/b0;

    .line 364
    .line 365
    iput-object v9, v7, Lg1/t1;->e:Lkotlin/jvm/internal/b0;

    .line 366
    .line 367
    const/4 v0, 0x3

    .line 368
    iput v0, v7, Lg1/t1;->g:I

    .line 369
    .line 370
    move/from16 v18, v0

    .line 371
    .line 372
    iget-object v0, v7, Lg1/t1;->m:Lb0/d1;

    .line 373
    .line 374
    iget-object v3, v7, Lg1/t1;->o:Lg1/u2;

    .line 375
    .line 376
    move-object v4, v6

    .line 377
    move-wide v5, v1

    .line 378
    move-object/from16 v1, v19

    .line 379
    .line 380
    move-object/from16 v2, v20

    .line 381
    .line 382
    invoke-static/range {v0 .. v7}, Lb0/d1;->b(Lb0/d1;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/c0;Lg1/u2;Lkotlin/jvm/internal/f0;JLrx0/c;)Ljava/lang/Object;

    .line 383
    .line 384
    .line 385
    move-result-object v0

    .line 386
    if-ne v0, v8, :cond_9

    .line 387
    .line 388
    goto :goto_7

    .line 389
    :cond_9
    move-object v3, v9

    .line 390
    :goto_4
    check-cast v0, Ljava/lang/Boolean;

    .line 391
    .line 392
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 393
    .line 394
    .line 395
    move-result v0

    .line 396
    iput-boolean v0, v9, Lkotlin/jvm/internal/b0;->d:Z

    .line 397
    .line 398
    :goto_5
    move-object v5, v4

    .line 399
    move-object v0, v10

    .line 400
    move v4, v14

    .line 401
    move/from16 v6, v18

    .line 402
    .line 403
    move-object v14, v3

    .line 404
    move v3, v11

    .line 405
    goto/16 :goto_1

    .line 406
    .line 407
    :cond_a
    const/16 v18, 0x3

    .line 408
    .line 409
    move-object v5, v6

    .line 410
    move-object v0, v10

    .line 411
    move v3, v11

    .line 412
    move v4, v14

    .line 413
    move/from16 v6, v18

    .line 414
    .line 415
    move-object/from16 v1, v19

    .line 416
    .line 417
    move-object/from16 v2, v20

    .line 418
    .line 419
    goto/16 :goto_0

    .line 420
    .line 421
    :goto_6
    invoke-virtual {v12, v13, v10}, Lb0/d1;->c(Lg1/t2;F)F

    .line 422
    .line 423
    .line 424
    iput-object v13, v7, Lg1/t1;->h:Ljava/lang/Object;

    .line 425
    .line 426
    iput-object v9, v7, Lg1/t1;->d:Lkotlin/jvm/internal/b0;

    .line 427
    .line 428
    iput-object v9, v7, Lg1/t1;->e:Lkotlin/jvm/internal/b0;

    .line 429
    .line 430
    iput v14, v7, Lg1/t1;->g:I

    .line 431
    .line 432
    iget-object v0, v7, Lg1/t1;->m:Lb0/d1;

    .line 433
    .line 434
    iget-object v3, v7, Lg1/t1;->o:Lg1/u2;

    .line 435
    .line 436
    const-wide/16 v5, 0x32

    .line 437
    .line 438
    invoke-static/range {v0 .. v7}, Lb0/d1;->b(Lb0/d1;Lkotlin/jvm/internal/f0;Lkotlin/jvm/internal/c0;Lg1/u2;Lkotlin/jvm/internal/f0;JLrx0/c;)Ljava/lang/Object;

    .line 439
    .line 440
    .line 441
    move-result-object v0

    .line 442
    if-ne v0, v8, :cond_b

    .line 443
    .line 444
    :goto_7
    return-object v8

    .line 445
    :cond_b
    move-object v3, v9

    .line 446
    move-object v10, v13

    .line 447
    :goto_8
    check-cast v0, Ljava/lang/Boolean;

    .line 448
    .line 449
    invoke-virtual {v0}, Ljava/lang/Boolean;->booleanValue()Z

    .line 450
    .line 451
    .line 452
    move-result v0

    .line 453
    iput-boolean v0, v9, Lkotlin/jvm/internal/b0;->d:Z

    .line 454
    .line 455
    move-object/from16 v7, p0

    .line 456
    .line 457
    goto :goto_5

    .line 458
    :cond_c
    return-object v16
.end method
