.class public final Lmx0/c0;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public e:Ljava/lang/Object;

.field public f:Ljava/util/Iterator;

.field public g:I

.field public h:I

.field public i:I

.field public synthetic j:Ljava/lang/Object;

.field public final synthetic k:I

.field public final synthetic l:I

.field public final synthetic m:Ljava/util/Iterator;


# direct methods
.method public constructor <init>(IILjava/util/Iterator;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lmx0/c0;->k:I

    .line 2
    .line 3
    iput p2, p0, Lmx0/c0;->l:I

    .line 4
    .line 5
    iput-object p3, p0, Lmx0/c0;->m:Ljava/util/Iterator;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    new-instance v0, Lmx0/c0;

    .line 2
    .line 3
    iget v1, p0, Lmx0/c0;->l:I

    .line 4
    .line 5
    iget-object v2, p0, Lmx0/c0;->m:Ljava/util/Iterator;

    .line 6
    .line 7
    iget p0, p0, Lmx0/c0;->k:I

    .line 8
    .line 9
    invoke-direct {v0, p0, v1, v2, p2}, Lmx0/c0;-><init>(IILjava/util/Iterator;Lkotlin/coroutines/Continuation;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Lmx0/c0;->j:Ljava/lang/Object;

    .line 13
    .line 14
    return-object v0
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lky0/k;

    .line 2
    .line 3
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Lmx0/c0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    check-cast p0, Lmx0/c0;

    .line 10
    .line 11
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    invoke-virtual {p0, p1}, Lmx0/c0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 19

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lmx0/c0;->j:Ljava/lang/Object;

    .line 4
    .line 5
    check-cast v1, Lky0/k;

    .line 6
    .line 7
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 8
    .line 9
    iget v3, v0, Lmx0/c0;->i:I

    .line 10
    .line 11
    const/4 v4, 0x5

    .line 12
    const/4 v5, 0x4

    .line 13
    const/4 v6, 0x3

    .line 14
    const/4 v7, 0x2

    .line 15
    iget v8, v0, Lmx0/c0;->l:I

    .line 16
    .line 17
    const/4 v9, 0x1

    .line 18
    iget v10, v0, Lmx0/c0;->k:I

    .line 19
    .line 20
    const/4 v11, 0x0

    .line 21
    if-eqz v3, :cond_5

    .line 22
    .line 23
    if-eq v3, v9, :cond_4

    .line 24
    .line 25
    if-eq v3, v7, :cond_3

    .line 26
    .line 27
    if-eq v3, v6, :cond_2

    .line 28
    .line 29
    if-eq v3, v5, :cond_1

    .line 30
    .line 31
    if-ne v3, v4, :cond_0

    .line 32
    .line 33
    iget-object v0, v0, Lmx0/c0;->e:Ljava/lang/Object;

    .line 34
    .line 35
    check-cast v0, Lmx0/b0;

    .line 36
    .line 37
    :goto_0
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    goto/16 :goto_6

    .line 41
    .line 42
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw v0

    .line 50
    :cond_1
    iget v3, v0, Lmx0/c0;->h:I

    .line 51
    .line 52
    iget v6, v0, Lmx0/c0;->g:I

    .line 53
    .line 54
    iget-object v7, v0, Lmx0/c0;->e:Ljava/lang/Object;

    .line 55
    .line 56
    check-cast v7, Lmx0/b0;

    .line 57
    .line 58
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    invoke-virtual {v7, v8}, Lmx0/b0;->e(I)V

    .line 62
    .line 63
    .line 64
    goto/16 :goto_5

    .line 65
    .line 66
    :cond_2
    iget v3, v0, Lmx0/c0;->h:I

    .line 67
    .line 68
    iget v7, v0, Lmx0/c0;->g:I

    .line 69
    .line 70
    iget-object v12, v0, Lmx0/c0;->f:Ljava/util/Iterator;

    .line 71
    .line 72
    iget-object v13, v0, Lmx0/c0;->e:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v13, Lmx0/b0;

    .line 75
    .line 76
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {v13, v8}, Lmx0/b0;->e(I)V

    .line 80
    .line 81
    .line 82
    goto/16 :goto_3

    .line 83
    .line 84
    :cond_3
    iget-object v0, v0, Lmx0/c0;->e:Ljava/lang/Object;

    .line 85
    .line 86
    check-cast v0, Ljava/util/ArrayList;

    .line 87
    .line 88
    goto :goto_0

    .line 89
    :cond_4
    iget v3, v0, Lmx0/c0;->h:I

    .line 90
    .line 91
    iget v4, v0, Lmx0/c0;->g:I

    .line 92
    .line 93
    iget-object v5, v0, Lmx0/c0;->f:Ljava/util/Iterator;

    .line 94
    .line 95
    iget-object v6, v0, Lmx0/c0;->e:Ljava/lang/Object;

    .line 96
    .line 97
    check-cast v6, Ljava/util/ArrayList;

    .line 98
    .line 99
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    new-instance v6, Ljava/util/ArrayList;

    .line 103
    .line 104
    invoke-direct {v6, v10}, Ljava/util/ArrayList;-><init>(I)V

    .line 105
    .line 106
    .line 107
    move v12, v3

    .line 108
    goto :goto_2

    .line 109
    :cond_5
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 110
    .line 111
    .line 112
    const/16 v3, 0x400

    .line 113
    .line 114
    if-le v10, v3, :cond_6

    .line 115
    .line 116
    goto :goto_1

    .line 117
    :cond_6
    move v3, v10

    .line 118
    :goto_1
    sub-int v12, v8, v10

    .line 119
    .line 120
    iget-object v13, v0, Lmx0/c0;->m:Ljava/util/Iterator;

    .line 121
    .line 122
    const/4 v14, 0x0

    .line 123
    if-ltz v12, :cond_a

    .line 124
    .line 125
    new-instance v6, Ljava/util/ArrayList;

    .line 126
    .line 127
    invoke-direct {v6, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 128
    .line 129
    .line 130
    move v4, v3

    .line 131
    move-object v5, v13

    .line 132
    move v3, v14

    .line 133
    :cond_7
    :goto_2
    invoke-interface {v5}, Ljava/util/Iterator;->hasNext()Z

    .line 134
    .line 135
    .line 136
    move-result v8

    .line 137
    if-eqz v8, :cond_9

    .line 138
    .line 139
    invoke-interface {v5}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 140
    .line 141
    .line 142
    move-result-object v8

    .line 143
    if-lez v3, :cond_8

    .line 144
    .line 145
    add-int/lit8 v3, v3, -0x1

    .line 146
    .line 147
    goto :goto_2

    .line 148
    :cond_8
    invoke-virtual {v6, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 149
    .line 150
    .line 151
    invoke-virtual {v6}, Ljava/util/ArrayList;->size()I

    .line 152
    .line 153
    .line 154
    move-result v8

    .line 155
    if-ne v8, v10, :cond_7

    .line 156
    .line 157
    iput-object v1, v0, Lmx0/c0;->j:Ljava/lang/Object;

    .line 158
    .line 159
    iput-object v6, v0, Lmx0/c0;->e:Ljava/lang/Object;

    .line 160
    .line 161
    iput-object v5, v0, Lmx0/c0;->f:Ljava/util/Iterator;

    .line 162
    .line 163
    iput v4, v0, Lmx0/c0;->g:I

    .line 164
    .line 165
    iput v12, v0, Lmx0/c0;->h:I

    .line 166
    .line 167
    iput v9, v0, Lmx0/c0;->i:I

    .line 168
    .line 169
    invoke-virtual {v1, v6, v0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 170
    .line 171
    .line 172
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 173
    .line 174
    return-object v2

    .line 175
    :cond_9
    invoke-interface {v6}, Ljava/util/Collection;->isEmpty()Z

    .line 176
    .line 177
    .line 178
    move-result v3

    .line 179
    if-nez v3, :cond_12

    .line 180
    .line 181
    iput-object v11, v0, Lmx0/c0;->j:Ljava/lang/Object;

    .line 182
    .line 183
    iput-object v11, v0, Lmx0/c0;->e:Ljava/lang/Object;

    .line 184
    .line 185
    iput-object v11, v0, Lmx0/c0;->f:Ljava/util/Iterator;

    .line 186
    .line 187
    iput v4, v0, Lmx0/c0;->g:I

    .line 188
    .line 189
    iput v12, v0, Lmx0/c0;->h:I

    .line 190
    .line 191
    iput v7, v0, Lmx0/c0;->i:I

    .line 192
    .line 193
    invoke-virtual {v1, v6, v0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 194
    .line 195
    .line 196
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 197
    .line 198
    return-object v2

    .line 199
    :cond_a
    new-instance v7, Lmx0/b0;

    .line 200
    .line 201
    new-array v15, v3, [Ljava/lang/Object;

    .line 202
    .line 203
    invoke-direct {v7, v15, v14}, Lmx0/b0;-><init>([Ljava/lang/Object;I)V

    .line 204
    .line 205
    .line 206
    move-object/from16 v18, v7

    .line 207
    .line 208
    move v7, v3

    .line 209
    move v3, v12

    .line 210
    move-object v12, v13

    .line 211
    move-object/from16 v13, v18

    .line 212
    .line 213
    :goto_3
    iget v14, v13, Lmx0/b0;->e:I

    .line 214
    .line 215
    iget-object v15, v13, Lmx0/b0;->d:[Ljava/lang/Object;

    .line 216
    .line 217
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 218
    .line 219
    .line 220
    move-result v16

    .line 221
    if-eqz v16, :cond_10

    .line 222
    .line 223
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 224
    .line 225
    .line 226
    move-result-object v16

    .line 227
    move/from16 v17, v9

    .line 228
    .line 229
    invoke-virtual {v13}, Lmx0/b0;->c()I

    .line 230
    .line 231
    .line 232
    move-result v9

    .line 233
    if-eq v9, v14, :cond_f

    .line 234
    .line 235
    iget v9, v13, Lmx0/b0;->f:I

    .line 236
    .line 237
    iget v4, v13, Lmx0/b0;->g:I

    .line 238
    .line 239
    add-int/2addr v9, v4

    .line 240
    rem-int/2addr v9, v14

    .line 241
    aput-object v16, v15, v9

    .line 242
    .line 243
    add-int/lit8 v4, v4, 0x1

    .line 244
    .line 245
    iput v4, v13, Lmx0/b0;->g:I

    .line 246
    .line 247
    invoke-virtual {v13}, Lmx0/b0;->c()I

    .line 248
    .line 249
    .line 250
    move-result v4

    .line 251
    if-ne v4, v14, :cond_d

    .line 252
    .line 253
    iget v4, v13, Lmx0/b0;->g:I

    .line 254
    .line 255
    if-ge v4, v10, :cond_e

    .line 256
    .line 257
    shr-int/lit8 v4, v14, 0x1

    .line 258
    .line 259
    add-int/2addr v14, v4

    .line 260
    add-int/lit8 v14, v14, 0x1

    .line 261
    .line 262
    if-le v14, v10, :cond_b

    .line 263
    .line 264
    move v14, v10

    .line 265
    :cond_b
    iget v4, v13, Lmx0/b0;->f:I

    .line 266
    .line 267
    if-nez v4, :cond_c

    .line 268
    .line 269
    invoke-static {v15, v14}, Ljava/util/Arrays;->copyOf([Ljava/lang/Object;I)[Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object v4

    .line 273
    const-string v9, "copyOf(...)"

    .line 274
    .line 275
    invoke-static {v4, v9}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 276
    .line 277
    .line 278
    goto :goto_4

    .line 279
    :cond_c
    new-array v4, v14, [Ljava/lang/Object;

    .line 280
    .line 281
    invoke-virtual {v13, v4}, Lmx0/b0;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    .line 282
    .line 283
    .line 284
    move-result-object v4

    .line 285
    :goto_4
    new-instance v9, Lmx0/b0;

    .line 286
    .line 287
    iget v13, v13, Lmx0/b0;->g:I

    .line 288
    .line 289
    invoke-direct {v9, v4, v13}, Lmx0/b0;-><init>([Ljava/lang/Object;I)V

    .line 290
    .line 291
    .line 292
    move-object v13, v9

    .line 293
    :cond_d
    move/from16 v9, v17

    .line 294
    .line 295
    const/4 v4, 0x5

    .line 296
    goto :goto_3

    .line 297
    :cond_e
    new-instance v4, Ljava/util/ArrayList;

    .line 298
    .line 299
    invoke-direct {v4, v13}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 300
    .line 301
    .line 302
    iput-object v1, v0, Lmx0/c0;->j:Ljava/lang/Object;

    .line 303
    .line 304
    iput-object v13, v0, Lmx0/c0;->e:Ljava/lang/Object;

    .line 305
    .line 306
    iput-object v12, v0, Lmx0/c0;->f:Ljava/util/Iterator;

    .line 307
    .line 308
    iput v7, v0, Lmx0/c0;->g:I

    .line 309
    .line 310
    iput v3, v0, Lmx0/c0;->h:I

    .line 311
    .line 312
    iput v6, v0, Lmx0/c0;->i:I

    .line 313
    .line 314
    invoke-virtual {v1, v4, v0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 315
    .line 316
    .line 317
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 318
    .line 319
    return-object v2

    .line 320
    :cond_f
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 321
    .line 322
    const-string v1, "ring buffer is full"

    .line 323
    .line 324
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 325
    .line 326
    .line 327
    throw v0

    .line 328
    :cond_10
    move v6, v7

    .line 329
    move-object v7, v13

    .line 330
    :goto_5
    iget v4, v7, Lmx0/b0;->g:I

    .line 331
    .line 332
    if-le v4, v8, :cond_11

    .line 333
    .line 334
    new-instance v4, Ljava/util/ArrayList;

    .line 335
    .line 336
    invoke-direct {v4, v7}, Ljava/util/ArrayList;-><init>(Ljava/util/Collection;)V

    .line 337
    .line 338
    .line 339
    iput-object v1, v0, Lmx0/c0;->j:Ljava/lang/Object;

    .line 340
    .line 341
    iput-object v7, v0, Lmx0/c0;->e:Ljava/lang/Object;

    .line 342
    .line 343
    iput-object v11, v0, Lmx0/c0;->f:Ljava/util/Iterator;

    .line 344
    .line 345
    iput v6, v0, Lmx0/c0;->g:I

    .line 346
    .line 347
    iput v3, v0, Lmx0/c0;->h:I

    .line 348
    .line 349
    iput v5, v0, Lmx0/c0;->i:I

    .line 350
    .line 351
    invoke-virtual {v1, v4, v0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 352
    .line 353
    .line 354
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 355
    .line 356
    return-object v2

    .line 357
    :cond_11
    invoke-virtual {v7}, Lmx0/a;->isEmpty()Z

    .line 358
    .line 359
    .line 360
    move-result v4

    .line 361
    if-nez v4, :cond_12

    .line 362
    .line 363
    iput-object v11, v0, Lmx0/c0;->j:Ljava/lang/Object;

    .line 364
    .line 365
    iput-object v11, v0, Lmx0/c0;->e:Ljava/lang/Object;

    .line 366
    .line 367
    iput-object v11, v0, Lmx0/c0;->f:Ljava/util/Iterator;

    .line 368
    .line 369
    iput v6, v0, Lmx0/c0;->g:I

    .line 370
    .line 371
    iput v3, v0, Lmx0/c0;->h:I

    .line 372
    .line 373
    const/4 v3, 0x5

    .line 374
    iput v3, v0, Lmx0/c0;->i:I

    .line 375
    .line 376
    invoke-virtual {v1, v7, v0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 377
    .line 378
    .line 379
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 380
    .line 381
    return-object v2

    .line 382
    :cond_12
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 383
    .line 384
    return-object v0
.end method
