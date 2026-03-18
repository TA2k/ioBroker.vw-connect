.class public abstract Lwk0/z1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Luk0/c0;

.field public final i:Luk0/b0;

.field public final j:Lhy0/d;

.field public final k:Ljava/lang/Object;

.field public final l:Ljava/lang/Object;

.field public final m:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Luk0/c0;Luk0/b0;Lhy0/d;)V
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    const-string v2, "type"

    .line 6
    .line 7
    invoke-static {v1, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    new-instance v3, Lwk0/x1;

    .line 11
    .line 12
    const/16 v18, 0x0

    .line 13
    .line 14
    const v19, 0xffff

    .line 15
    .line 16
    .line 17
    const/4 v4, 0x0

    .line 18
    const/4 v5, 0x0

    .line 19
    const/4 v6, 0x0

    .line 20
    const/4 v7, 0x0

    .line 21
    const/4 v8, 0x0

    .line 22
    const/4 v9, 0x0

    .line 23
    const/4 v10, 0x0

    .line 24
    const/4 v11, 0x0

    .line 25
    const/4 v12, 0x0

    .line 26
    const/4 v13, 0x0

    .line 27
    const/4 v14, 0x0

    .line 28
    const/4 v15, 0x0

    .line 29
    const/16 v16, 0x0

    .line 30
    .line 31
    const/16 v17, 0x0

    .line 32
    .line 33
    invoke-direct/range {v3 .. v19}, Lwk0/x1;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lwk0/f1;Ljava/lang/Boolean;Ljava/util/Map;Ljava/util/List;Ljava/lang/String;ZLwk0/t;Lwk0/j0;Ljava/lang/Object;ZZI)V

    .line 34
    .line 35
    .line 36
    invoke-direct {v0, v3}, Lql0/j;-><init>(Lql0/h;)V

    .line 37
    .line 38
    .line 39
    move-object/from16 v2, p1

    .line 40
    .line 41
    iput-object v2, v0, Lwk0/z1;->h:Luk0/c0;

    .line 42
    .line 43
    move-object/from16 v2, p2

    .line 44
    .line 45
    iput-object v2, v0, Lwk0/z1;->i:Luk0/b0;

    .line 46
    .line 47
    iput-object v1, v0, Lwk0/z1;->j:Lhy0/d;

    .line 48
    .line 49
    const-class v1, Lcs0/l;

    .line 50
    .line 51
    invoke-static {v1}, Ljp/w1;->c(Ljava/lang/Class;)Llx0/i;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    iput-object v1, v0, Lwk0/z1;->k:Ljava/lang/Object;

    .line 56
    .line 57
    const-class v1, Lpp0/z;

    .line 58
    .line 59
    invoke-static {v1}, Ljp/w1;->c(Ljava/lang/Class;)Llx0/i;

    .line 60
    .line 61
    .line 62
    move-result-object v1

    .line 63
    iput-object v1, v0, Lwk0/z1;->l:Ljava/lang/Object;

    .line 64
    .line 65
    const-class v1, Lij0/a;

    .line 66
    .line 67
    invoke-static {v1}, Ljp/w1;->c(Ljava/lang/Class;)Llx0/i;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    iput-object v1, v0, Lwk0/z1;->m:Ljava/lang/Object;

    .line 72
    .line 73
    new-instance v1, Lwk0/u1;

    .line 74
    .line 75
    const/4 v2, 0x0

    .line 76
    const/4 v3, 0x0

    .line 77
    invoke-direct {v1, v0, v3, v2}, Lwk0/u1;-><init>(Lwk0/z1;Lkotlin/coroutines/Continuation;I)V

    .line 78
    .line 79
    .line 80
    invoke-virtual {v0, v1}, Lql0/j;->b(Lay0/n;)V

    .line 81
    .line 82
    .line 83
    new-instance v1, Lwk0/u1;

    .line 84
    .line 85
    const/4 v2, 0x1

    .line 86
    invoke-direct {v1, v0, v3, v2}, Lwk0/u1;-><init>(Lwk0/z1;Lkotlin/coroutines/Continuation;I)V

    .line 87
    .line 88
    .line 89
    invoke-virtual {v0, v1}, Lql0/j;->b(Lay0/n;)V

    .line 90
    .line 91
    .line 92
    return-void
.end method

.method public static final h(Lwk0/z1;Lvk0/j0;Lrx0/c;)Ljava/lang/Object;
    .locals 32

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    iget-object v2, v0, Lwk0/z1;->m:Ljava/lang/Object;

    .line 6
    .line 7
    instance-of v3, v1, Lwk0/y1;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v1

    .line 12
    check-cast v3, Lwk0/y1;

    .line 13
    .line 14
    iget v4, v3, Lwk0/y1;->l:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lwk0/y1;->l:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lwk0/y1;

    .line 27
    .line 28
    invoke-direct {v3, v0, v1}, Lwk0/y1;-><init>(Lwk0/z1;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v1, v3, Lwk0/y1;->j:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lwk0/y1;->l:I

    .line 36
    .line 37
    const/4 v6, 0x3

    .line 38
    const/4 v7, 0x2

    .line 39
    const/4 v8, 0x1

    .line 40
    const/4 v9, 0x0

    .line 41
    if-eqz v5, :cond_4

    .line 42
    .line 43
    if-eq v5, v8, :cond_3

    .line 44
    .line 45
    if-eq v5, v7, :cond_2

    .line 46
    .line 47
    if-ne v5, v6, :cond_1

    .line 48
    .line 49
    iget-object v0, v3, Lwk0/y1;->e:Ljava/lang/String;

    .line 50
    .line 51
    check-cast v0, Lwk0/x1;

    .line 52
    .line 53
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    return-object v1

    .line 57
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw v0

    .line 65
    :cond_2
    iget-object v5, v3, Lwk0/y1;->i:Lij0/a;

    .line 66
    .line 67
    iget-object v7, v3, Lwk0/y1;->h:Loo0/b;

    .line 68
    .line 69
    iget-object v10, v3, Lwk0/y1;->g:Ljava/lang/String;

    .line 70
    .line 71
    iget-object v11, v3, Lwk0/y1;->f:Ljava/lang/String;

    .line 72
    .line 73
    iget-object v12, v3, Lwk0/y1;->e:Ljava/lang/String;

    .line 74
    .line 75
    iget-object v13, v3, Lwk0/y1;->d:Lvk0/j0;

    .line 76
    .line 77
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    goto/16 :goto_3

    .line 81
    .line 82
    :cond_3
    iget-object v5, v3, Lwk0/y1;->i:Lij0/a;

    .line 83
    .line 84
    check-cast v5, Loo0/b;

    .line 85
    .line 86
    iget-object v5, v3, Lwk0/y1;->h:Loo0/b;

    .line 87
    .line 88
    iget-object v10, v3, Lwk0/y1;->g:Ljava/lang/String;

    .line 89
    .line 90
    iget-object v11, v3, Lwk0/y1;->f:Ljava/lang/String;

    .line 91
    .line 92
    iget-object v12, v3, Lwk0/y1;->e:Ljava/lang/String;

    .line 93
    .line 94
    iget-object v13, v3, Lwk0/y1;->d:Lvk0/j0;

    .line 95
    .line 96
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 97
    .line 98
    .line 99
    goto :goto_1

    .line 100
    :cond_4
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 101
    .line 102
    .line 103
    invoke-interface/range {p1 .. p1}, Lvk0/j0;->getId()Ljava/lang/String;

    .line 104
    .line 105
    .line 106
    move-result-object v1

    .line 107
    invoke-interface/range {p1 .. p1}, Lvk0/j0;->getName()Ljava/lang/String;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    if-nez v5, :cond_5

    .line 112
    .line 113
    const-string v5, ""

    .line 114
    .line 115
    :cond_5
    invoke-interface/range {p1 .. p1}, Lvk0/j0;->b()Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v10

    .line 119
    invoke-interface/range {p1 .. p1}, Lvk0/j0;->h()Loo0/b;

    .line 120
    .line 121
    .line 122
    move-result-object v11

    .line 123
    iget-object v12, v0, Lwk0/z1;->l:Ljava/lang/Object;

    .line 124
    .line 125
    invoke-interface {v12}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v12

    .line 129
    check-cast v12, Lpp0/z;

    .line 130
    .line 131
    move-object/from16 v13, p1

    .line 132
    .line 133
    iput-object v13, v3, Lwk0/y1;->d:Lvk0/j0;

    .line 134
    .line 135
    iput-object v1, v3, Lwk0/y1;->e:Ljava/lang/String;

    .line 136
    .line 137
    iput-object v5, v3, Lwk0/y1;->f:Ljava/lang/String;

    .line 138
    .line 139
    iput-object v10, v3, Lwk0/y1;->g:Ljava/lang/String;

    .line 140
    .line 141
    iput-object v11, v3, Lwk0/y1;->h:Loo0/b;

    .line 142
    .line 143
    iput-object v9, v3, Lwk0/y1;->i:Lij0/a;

    .line 144
    .line 145
    iput v8, v3, Lwk0/y1;->l:I

    .line 146
    .line 147
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 148
    .line 149
    .line 150
    invoke-virtual {v12, v3}, Lpp0/z;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v12

    .line 154
    if-ne v12, v4, :cond_6

    .line 155
    .line 156
    goto/16 :goto_10

    .line 157
    .line 158
    :cond_6
    move-object/from16 v31, v12

    .line 159
    .line 160
    move-object v12, v1

    .line 161
    move-object/from16 v1, v31

    .line 162
    .line 163
    move-object/from16 v31, v11

    .line 164
    .line 165
    move-object v11, v5

    .line 166
    move-object/from16 v5, v31

    .line 167
    .line 168
    :goto_1
    check-cast v1, Ljava/lang/Boolean;

    .line 169
    .line 170
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 171
    .line 172
    .line 173
    move-result v1

    .line 174
    if-nez v1, :cond_7

    .line 175
    .line 176
    goto :goto_2

    .line 177
    :cond_7
    move-object v5, v9

    .line 178
    :goto_2
    if-eqz v5, :cond_9

    .line 179
    .line 180
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object v1

    .line 184
    check-cast v1, Lij0/a;

    .line 185
    .line 186
    iget-object v14, v0, Lwk0/z1;->k:Ljava/lang/Object;

    .line 187
    .line 188
    invoke-interface {v14}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    move-result-object v14

    .line 192
    check-cast v14, Lcs0/l;

    .line 193
    .line 194
    iput-object v13, v3, Lwk0/y1;->d:Lvk0/j0;

    .line 195
    .line 196
    iput-object v12, v3, Lwk0/y1;->e:Ljava/lang/String;

    .line 197
    .line 198
    iput-object v11, v3, Lwk0/y1;->f:Ljava/lang/String;

    .line 199
    .line 200
    iput-object v10, v3, Lwk0/y1;->g:Ljava/lang/String;

    .line 201
    .line 202
    iput-object v5, v3, Lwk0/y1;->h:Loo0/b;

    .line 203
    .line 204
    iput-object v1, v3, Lwk0/y1;->i:Lij0/a;

    .line 205
    .line 206
    iput v7, v3, Lwk0/y1;->l:I

    .line 207
    .line 208
    invoke-virtual {v14}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 209
    .line 210
    .line 211
    invoke-virtual {v14, v3}, Lcs0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 212
    .line 213
    .line 214
    move-result-object v7

    .line 215
    if-ne v7, v4, :cond_8

    .line 216
    .line 217
    goto/16 :goto_10

    .line 218
    .line 219
    :cond_8
    move-object/from16 v31, v5

    .line 220
    .line 221
    move-object v5, v1

    .line 222
    move-object v1, v7

    .line 223
    move-object/from16 v7, v31

    .line 224
    .line 225
    :goto_3
    check-cast v1, Lqr0/s;

    .line 226
    .line 227
    invoke-static {v7, v5, v1}, Ljp/qd;->c(Loo0/b;Lij0/a;Lqr0/s;)Ljava/lang/String;

    .line 228
    .line 229
    .line 230
    move-result-object v1

    .line 231
    move-object/from16 v18, v1

    .line 232
    .line 233
    :goto_4
    move-object/from16 v17, v10

    .line 234
    .line 235
    move-object/from16 v16, v11

    .line 236
    .line 237
    move-object v15, v12

    .line 238
    goto :goto_5

    .line 239
    :cond_9
    move-object/from16 v18, v9

    .line 240
    .line 241
    goto :goto_4

    .line 242
    :goto_5
    invoke-interface {v13}, Lvk0/j0;->d()Lvk0/i0;

    .line 243
    .line 244
    .line 245
    move-result-object v1

    .line 246
    if-eqz v1, :cond_d

    .line 247
    .line 248
    iget-object v5, v1, Lvk0/i0;->a:Ljava/lang/Float;

    .line 249
    .line 250
    if-eqz v5, :cond_a

    .line 251
    .line 252
    invoke-virtual {v5}, Ljava/lang/Float;->floatValue()F

    .line 253
    .line 254
    .line 255
    move-result v5

    .line 256
    const/4 v7, 0x0

    .line 257
    cmpl-float v5, v5, v7

    .line 258
    .line 259
    if-lez v5, :cond_a

    .line 260
    .line 261
    goto :goto_6

    .line 262
    :cond_a
    move-object v1, v9

    .line 263
    :goto_6
    if-eqz v1, :cond_d

    .line 264
    .line 265
    iget-object v5, v1, Lvk0/i0;->a:Ljava/lang/Float;

    .line 266
    .line 267
    if-eqz v5, :cond_c

    .line 268
    .line 269
    invoke-virtual {v5}, Ljava/lang/Float;->floatValue()F

    .line 270
    .line 271
    .line 272
    move-result v5

    .line 273
    invoke-static {v5}, Ljava/lang/String;->valueOf(F)Ljava/lang/String;

    .line 274
    .line 275
    .line 276
    move-result-object v5

    .line 277
    if-nez v5, :cond_b

    .line 278
    .line 279
    goto :goto_7

    .line 280
    :cond_b
    new-instance v7, Lwk0/f1;

    .line 281
    .line 282
    iget-object v1, v1, Lvk0/i0;->b:Ljava/lang/Integer;

    .line 283
    .line 284
    invoke-direct {v7, v5, v1}, Lwk0/f1;-><init>(Ljava/lang/String;Ljava/lang/Integer;)V

    .line 285
    .line 286
    .line 287
    goto :goto_8

    .line 288
    :cond_c
    :goto_7
    move-object v7, v9

    .line 289
    :goto_8
    move-object/from16 v19, v7

    .line 290
    .line 291
    goto :goto_9

    .line 292
    :cond_d
    move-object/from16 v19, v9

    .line 293
    .line 294
    :goto_9
    invoke-interface {v13}, Lvk0/j0;->i()Ljava/lang/Boolean;

    .line 295
    .line 296
    .line 297
    move-result-object v20

    .line 298
    invoke-interface {v13}, Lvk0/j0;->g()Ljava/util/List;

    .line 299
    .line 300
    .line 301
    move-result-object v1

    .line 302
    check-cast v1, Ljava/lang/Iterable;

    .line 303
    .line 304
    new-instance v5, Ljava/util/ArrayList;

    .line 305
    .line 306
    const/16 v7, 0xa

    .line 307
    .line 308
    invoke-static {v1, v7}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 309
    .line 310
    .line 311
    move-result v7

    .line 312
    invoke-direct {v5, v7}, Ljava/util/ArrayList;-><init>(I)V

    .line 313
    .line 314
    .line 315
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 316
    .line 317
    .line 318
    move-result-object v1

    .line 319
    :goto_a
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 320
    .line 321
    .line 322
    move-result v7

    .line 323
    if-eqz v7, :cond_e

    .line 324
    .line 325
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 326
    .line 327
    .line 328
    move-result-object v7

    .line 329
    check-cast v7, Ljava/net/URL;

    .line 330
    .line 331
    invoke-static {v7}, Ljp/sf;->h(Ljava/net/URL;)Landroid/net/Uri;

    .line 332
    .line 333
    .line 334
    move-result-object v7

    .line 335
    invoke-virtual {v5, v7}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 336
    .line 337
    .line 338
    goto :goto_a

    .line 339
    :cond_e
    invoke-interface {v13}, Lvk0/j0;->getDescription()Ljava/lang/String;

    .line 340
    .line 341
    .line 342
    move-result-object v23

    .line 343
    invoke-interface {v13}, Lvk0/j0;->g()Ljava/util/List;

    .line 344
    .line 345
    .line 346
    move-result-object v1

    .line 347
    check-cast v1, Ljava/util/Collection;

    .line 348
    .line 349
    invoke-interface {v1}, Ljava/util/Collection;->isEmpty()Z

    .line 350
    .line 351
    .line 352
    move-result v1

    .line 353
    xor-int/lit8 v24, v1, 0x1

    .line 354
    .line 355
    invoke-interface {v13}, Lvk0/j0;->e()Ljava/util/List;

    .line 356
    .line 357
    .line 358
    move-result-object v1

    .line 359
    if-eqz v1, :cond_10

    .line 360
    .line 361
    move-object v7, v1

    .line 362
    check-cast v7, Ljava/util/Collection;

    .line 363
    .line 364
    invoke-interface {v7}, Ljava/util/Collection;->isEmpty()Z

    .line 365
    .line 366
    .line 367
    move-result v7

    .line 368
    if-nez v7, :cond_f

    .line 369
    .line 370
    goto :goto_b

    .line 371
    :cond_f
    move-object v1, v9

    .line 372
    :goto_b
    if-eqz v1, :cond_10

    .line 373
    .line 374
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object v7

    .line 378
    check-cast v7, Lij0/a;

    .line 379
    .line 380
    invoke-static {v7, v1}, Llp/kd;->b(Lij0/a;Ljava/util/List;)Ljava/util/LinkedHashMap;

    .line 381
    .line 382
    .line 383
    move-result-object v1

    .line 384
    move-object/from16 v21, v1

    .line 385
    .line 386
    goto :goto_c

    .line 387
    :cond_10
    move-object/from16 v21, v9

    .line 388
    .line 389
    :goto_c
    invoke-interface {v13}, Lvk0/j0;->f()Lvk0/y;

    .line 390
    .line 391
    .line 392
    move-result-object v1

    .line 393
    if-eqz v1, :cond_11

    .line 394
    .line 395
    invoke-interface {v2}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 396
    .line 397
    .line 398
    move-result-object v2

    .line 399
    check-cast v2, Lij0/a;

    .line 400
    .line 401
    invoke-static {v1, v2}, Llp/jd;->c(Lvk0/y;Lij0/a;)Lwk0/j0;

    .line 402
    .line 403
    .line 404
    move-result-object v1

    .line 405
    move-object/from16 v26, v1

    .line 406
    .line 407
    goto :goto_d

    .line 408
    :cond_11
    move-object/from16 v26, v9

    .line 409
    .line 410
    :goto_d
    invoke-interface {v13}, Lvk0/j0;->c()Lvk0/l;

    .line 411
    .line 412
    .line 413
    move-result-object v1

    .line 414
    if-eqz v1, :cond_13

    .line 415
    .line 416
    new-instance v2, Lwk0/t;

    .line 417
    .line 418
    iget-object v7, v1, Lvk0/l;->a:Ljava/lang/String;

    .line 419
    .line 420
    iget-object v1, v1, Lvk0/l;->b:Ljava/net/URL;

    .line 421
    .line 422
    if-eqz v1, :cond_12

    .line 423
    .line 424
    new-instance v8, Lwk0/u2;

    .line 425
    .line 426
    invoke-virtual {v1}, Ljava/net/URL;->getHost()Ljava/lang/String;

    .line 427
    .line 428
    .line 429
    move-result-object v10

    .line 430
    const-string v11, "getHost(...)"

    .line 431
    .line 432
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 433
    .line 434
    .line 435
    invoke-virtual {v1}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 436
    .line 437
    .line 438
    move-result-object v1

    .line 439
    const-string v11, "toString(...)"

    .line 440
    .line 441
    invoke-static {v1, v11}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 442
    .line 443
    .line 444
    invoke-direct {v8, v10, v1}, Lwk0/u2;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 445
    .line 446
    .line 447
    goto :goto_e

    .line 448
    :cond_12
    move-object v8, v9

    .line 449
    :goto_e
    invoke-direct {v2, v7, v8}, Lwk0/t;-><init>(Ljava/lang/String;Lwk0/u2;)V

    .line 450
    .line 451
    .line 452
    move-object/from16 v25, v2

    .line 453
    .line 454
    goto :goto_f

    .line 455
    :cond_13
    move-object/from16 v25, v9

    .line 456
    .line 457
    :goto_f
    new-instance v14, Lwk0/x1;

    .line 458
    .line 459
    const/16 v29, 0x0

    .line 460
    .line 461
    const/16 v30, 0x1000

    .line 462
    .line 463
    const/16 v27, 0x0

    .line 464
    .line 465
    const/16 v28, 0x0

    .line 466
    .line 467
    move-object/from16 v22, v5

    .line 468
    .line 469
    invoke-direct/range {v14 .. v30}, Lwk0/x1;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lwk0/f1;Ljava/lang/Boolean;Ljava/util/Map;Ljava/util/List;Ljava/lang/String;ZLwk0/t;Lwk0/j0;Ljava/lang/Object;ZZI)V

    .line 470
    .line 471
    .line 472
    iput-object v9, v3, Lwk0/y1;->d:Lvk0/j0;

    .line 473
    .line 474
    iput-object v9, v3, Lwk0/y1;->e:Ljava/lang/String;

    .line 475
    .line 476
    iput-object v9, v3, Lwk0/y1;->f:Ljava/lang/String;

    .line 477
    .line 478
    iput-object v9, v3, Lwk0/y1;->g:Ljava/lang/String;

    .line 479
    .line 480
    iput-object v9, v3, Lwk0/y1;->h:Loo0/b;

    .line 481
    .line 482
    iput-object v9, v3, Lwk0/y1;->i:Lij0/a;

    .line 483
    .line 484
    iput v6, v3, Lwk0/y1;->l:I

    .line 485
    .line 486
    invoke-virtual {v0, v14, v13, v3}, Lwk0/z1;->j(Lwk0/x1;Lvk0/j0;Lwk0/y1;)Ljava/lang/Object;

    .line 487
    .line 488
    .line 489
    move-result-object v0

    .line 490
    if-ne v0, v4, :cond_14

    .line 491
    .line 492
    :goto_10
    return-object v4

    .line 493
    :cond_14
    return-object v0
.end method


# virtual methods
.method public j(Lwk0/x1;Lvk0/j0;Lwk0/y1;)Ljava/lang/Object;
    .locals 0

    .line 1
    return-object p1
.end method
