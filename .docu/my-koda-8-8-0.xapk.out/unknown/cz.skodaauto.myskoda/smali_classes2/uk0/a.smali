.class public final Luk0/a;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public d:I

.field public synthetic e:Lyy0/j;

.field public synthetic f:Ljava/lang/Object;

.field public g:Lyy0/j;

.field public h:I

.field public final synthetic i:Luk0/d;

.field public j:Lvk0/j0;

.field public k:Ljava/lang/String;

.field public l:I


# direct methods
.method public constructor <init>(Lkotlin/coroutines/Continuation;Luk0/d;)V
    .locals 0

    .line 1
    iput-object p2, p0, Luk0/a;->i:Luk0/d;

    .line 2
    .line 3
    const/4 p2, 0x3

    .line 4
    invoke-direct {p0, p2, p1}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    check-cast p1, Lyy0/j;

    .line 2
    .line 3
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 4
    .line 5
    new-instance v0, Luk0/a;

    .line 6
    .line 7
    iget-object p0, p0, Luk0/a;->i:Luk0/d;

    .line 8
    .line 9
    invoke-direct {v0, p3, p0}, Luk0/a;-><init>(Lkotlin/coroutines/Continuation;Luk0/d;)V

    .line 10
    .line 11
    .line 12
    iput-object p1, v0, Luk0/a;->e:Lyy0/j;

    .line 13
    .line 14
    iput-object p2, v0, Luk0/a;->f:Ljava/lang/Object;

    .line 15
    .line 16
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {v0, p0}, Luk0/a;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 4
    .line 5
    iget v2, v0, Luk0/a;->d:I

    .line 6
    .line 7
    const/4 v3, 0x3

    .line 8
    const/4 v4, 0x2

    .line 9
    iget-object v5, v0, Luk0/a;->i:Luk0/d;

    .line 10
    .line 11
    const/4 v6, 0x1

    .line 12
    const/4 v7, 0x0

    .line 13
    if-eqz v2, :cond_3

    .line 14
    .line 15
    if-eq v2, v6, :cond_2

    .line 16
    .line 17
    if-eq v2, v4, :cond_1

    .line 18
    .line 19
    if-ne v2, v3, :cond_0

    .line 20
    .line 21
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    goto/16 :goto_8

    .line 25
    .line 26
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 27
    .line 28
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 29
    .line 30
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw v0

    .line 34
    :cond_1
    iget-object v2, v0, Luk0/a;->k:Ljava/lang/String;

    .line 35
    .line 36
    iget-object v4, v0, Luk0/a;->g:Lyy0/j;

    .line 37
    .line 38
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    move-object v9, v4

    .line 42
    move-object/from16 v4, p1

    .line 43
    .line 44
    goto/16 :goto_4

    .line 45
    .line 46
    :cond_2
    iget v2, v0, Luk0/a;->l:I

    .line 47
    .line 48
    iget v6, v0, Luk0/a;->h:I

    .line 49
    .line 50
    iget-object v8, v0, Luk0/a;->j:Lvk0/j0;

    .line 51
    .line 52
    iget-object v9, v0, Luk0/a;->g:Lyy0/j;

    .line 53
    .line 54
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    move v10, v2

    .line 58
    move-object/from16 v2, p1

    .line 59
    .line 60
    goto :goto_0

    .line 61
    :cond_3
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    iget-object v9, v0, Luk0/a;->e:Lyy0/j;

    .line 65
    .line 66
    iget-object v2, v0, Luk0/a;->f:Ljava/lang/Object;

    .line 67
    .line 68
    check-cast v2, Lne0/t;

    .line 69
    .line 70
    instance-of v8, v2, Lne0/e;

    .line 71
    .line 72
    if-eqz v8, :cond_13

    .line 73
    .line 74
    check-cast v2, Lne0/e;

    .line 75
    .line 76
    iget-object v2, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 77
    .line 78
    move-object v8, v2

    .line 79
    check-cast v8, Lvk0/j0;

    .line 80
    .line 81
    invoke-interface {v8}, Lvk0/j0;->a()Ljava/lang/String;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    const/4 v10, 0x0

    .line 86
    if-nez v2, :cond_6

    .line 87
    .line 88
    iget-object v2, v5, Luk0/d;->b:Llk0/f;

    .line 89
    .line 90
    invoke-interface {v8}, Lvk0/j0;->getId()Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object v11

    .line 94
    iput-object v7, v0, Luk0/a;->e:Lyy0/j;

    .line 95
    .line 96
    iput-object v7, v0, Luk0/a;->f:Ljava/lang/Object;

    .line 97
    .line 98
    iput-object v9, v0, Luk0/a;->g:Lyy0/j;

    .line 99
    .line 100
    iput-object v8, v0, Luk0/a;->j:Lvk0/j0;

    .line 101
    .line 102
    iput v10, v0, Luk0/a;->h:I

    .line 103
    .line 104
    iput v10, v0, Luk0/a;->l:I

    .line 105
    .line 106
    iput v6, v0, Luk0/a;->d:I

    .line 107
    .line 108
    invoke-virtual {v2, v11, v0}, Llk0/f;->b(Ljava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object v2

    .line 112
    if-ne v2, v1, :cond_4

    .line 113
    .line 114
    goto/16 :goto_7

    .line 115
    .line 116
    :cond_4
    move v6, v10

    .line 117
    :goto_0
    check-cast v2, Lmk0/a;

    .line 118
    .line 119
    if-eqz v2, :cond_5

    .line 120
    .line 121
    iget-object v2, v2, Lmk0/a;->a:Ljava/lang/String;

    .line 122
    .line 123
    move/from16 v19, v10

    .line 124
    .line 125
    move v10, v6

    .line 126
    move/from16 v6, v19

    .line 127
    .line 128
    goto :goto_1

    .line 129
    :cond_5
    move v2, v10

    .line 130
    move v10, v6

    .line 131
    move v6, v2

    .line 132
    move-object v2, v7

    .line 133
    goto :goto_1

    .line 134
    :cond_6
    move v6, v10

    .line 135
    :goto_1
    if-eqz v2, :cond_7

    .line 136
    .line 137
    iget-object v4, v5, Luk0/d;->d:Llk0/k;

    .line 138
    .line 139
    iget-object v5, v4, Llk0/k;->b:Ljk0/c;

    .line 140
    .line 141
    iget-object v6, v5, Ljk0/c;->a:Lxl0/f;

    .line 142
    .line 143
    new-instance v8, La2/c;

    .line 144
    .line 145
    const/16 v10, 0x15

    .line 146
    .line 147
    invoke-direct {v8, v10, v5, v2, v7}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 148
    .line 149
    .line 150
    invoke-virtual {v6, v8}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 151
    .line 152
    .line 153
    move-result-object v5

    .line 154
    new-instance v6, La10/a;

    .line 155
    .line 156
    const/16 v8, 0x19

    .line 157
    .line 158
    invoke-direct {v6, v4, v7, v8}, La10/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 159
    .line 160
    .line 161
    invoke-static {v6, v5}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 162
    .line 163
    .line 164
    move-result-object v4

    .line 165
    invoke-static {v4}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 166
    .line 167
    .line 168
    move-result-object v4

    .line 169
    goto/16 :goto_5

    .line 170
    .line 171
    :cond_7
    iget-object v5, v5, Luk0/d;->a:Llk0/a;

    .line 172
    .line 173
    const-string v11, "<this>"

    .line 174
    .line 175
    invoke-static {v8, v11}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 176
    .line 177
    .line 178
    new-instance v12, Lmk0/c;

    .line 179
    .line 180
    instance-of v11, v8, Lvk0/j;

    .line 181
    .line 182
    if-eqz v11, :cond_8

    .line 183
    .line 184
    sget-object v11, Lmk0/b;->f:Lmk0/b;

    .line 185
    .line 186
    :goto_2
    move-object v14, v11

    .line 187
    goto :goto_3

    .line 188
    :cond_8
    instance-of v11, v8, Lvk0/p;

    .line 189
    .line 190
    if-eqz v11, :cond_9

    .line 191
    .line 192
    sget-object v11, Lmk0/b;->l:Lmk0/b;

    .line 193
    .line 194
    goto :goto_2

    .line 195
    :cond_9
    instance-of v11, v8, Lvk0/q;

    .line 196
    .line 197
    if-eqz v11, :cond_a

    .line 198
    .line 199
    sget-object v11, Lmk0/b;->k:Lmk0/b;

    .line 200
    .line 201
    goto :goto_2

    .line 202
    :cond_a
    instance-of v11, v8, Lvk0/c0;

    .line 203
    .line 204
    if-eqz v11, :cond_b

    .line 205
    .line 206
    sget-object v11, Lmk0/b;->h:Lmk0/b;

    .line 207
    .line 208
    goto :goto_2

    .line 209
    :cond_b
    instance-of v11, v8, Lvk0/d0;

    .line 210
    .line 211
    if-eqz v11, :cond_d

    .line 212
    .line 213
    move-object v11, v8

    .line 214
    check-cast v11, Lvk0/d0;

    .line 215
    .line 216
    iget-boolean v11, v11, Lvk0/d0;->n:Z

    .line 217
    .line 218
    if-eqz v11, :cond_c

    .line 219
    .line 220
    sget-object v11, Lmk0/b;->j:Lmk0/b;

    .line 221
    .line 222
    goto :goto_2

    .line 223
    :cond_c
    sget-object v11, Lmk0/b;->i:Lmk0/b;

    .line 224
    .line 225
    goto :goto_2

    .line 226
    :cond_d
    instance-of v11, v8, Lvk0/s0;

    .line 227
    .line 228
    if-eqz v11, :cond_e

    .line 229
    .line 230
    sget-object v11, Lmk0/b;->m:Lmk0/b;

    .line 231
    .line 232
    goto :goto_2

    .line 233
    :cond_e
    instance-of v11, v8, Lvk0/t;

    .line 234
    .line 235
    if-eqz v11, :cond_f

    .line 236
    .line 237
    sget-object v11, Lmk0/b;->g:Lmk0/b;

    .line 238
    .line 239
    goto :goto_2

    .line 240
    :cond_f
    instance-of v11, v8, Lvk0/t0;

    .line 241
    .line 242
    if-eqz v11, :cond_10

    .line 243
    .line 244
    sget-object v11, Lmk0/b;->n:Lmk0/b;

    .line 245
    .line 246
    goto :goto_2

    .line 247
    :cond_10
    instance-of v11, v8, Lvk0/v;

    .line 248
    .line 249
    if-eqz v11, :cond_12

    .line 250
    .line 251
    sget-object v11, Lmk0/b;->n:Lmk0/b;

    .line 252
    .line 253
    goto :goto_2

    .line 254
    :goto_3
    invoke-interface {v8}, Lvk0/j0;->getId()Ljava/lang/String;

    .line 255
    .line 256
    .line 257
    move-result-object v15

    .line 258
    invoke-interface {v8}, Lvk0/j0;->getLocation()Lxj0/f;

    .line 259
    .line 260
    .line 261
    move-result-object v16

    .line 262
    invoke-interface {v8}, Lvk0/j0;->b()Ljava/lang/String;

    .line 263
    .line 264
    .line 265
    move-result-object v17

    .line 266
    invoke-interface {v8}, Lvk0/j0;->getName()Ljava/lang/String;

    .line 267
    .line 268
    .line 269
    move-result-object v18

    .line 270
    const/4 v13, 0x0

    .line 271
    invoke-direct/range {v12 .. v18}, Lmk0/c;-><init>(Ljava/lang/String;Lmk0/b;Ljava/lang/String;Lxj0/f;Ljava/lang/String;Ljava/lang/String;)V

    .line 272
    .line 273
    .line 274
    iput-object v7, v0, Luk0/a;->e:Lyy0/j;

    .line 275
    .line 276
    iput-object v7, v0, Luk0/a;->f:Ljava/lang/Object;

    .line 277
    .line 278
    iput-object v9, v0, Luk0/a;->g:Lyy0/j;

    .line 279
    .line 280
    iput-object v7, v0, Luk0/a;->j:Lvk0/j0;

    .line 281
    .line 282
    iput-object v2, v0, Luk0/a;->k:Ljava/lang/String;

    .line 283
    .line 284
    iput v10, v0, Luk0/a;->h:I

    .line 285
    .line 286
    iput v6, v0, Luk0/a;->l:I

    .line 287
    .line 288
    iput v4, v0, Luk0/a;->d:I

    .line 289
    .line 290
    iget-object v4, v5, Llk0/a;->c:Ljk0/c;

    .line 291
    .line 292
    iget-object v6, v4, Ljk0/c;->a:Lxl0/f;

    .line 293
    .line 294
    new-instance v8, Ljk0/b;

    .line 295
    .line 296
    const/4 v10, 0x0

    .line 297
    invoke-direct {v8, v4, v12, v7, v10}, Ljk0/b;-><init>(Ljk0/c;Lmk0/c;Lkotlin/coroutines/Continuation;I)V

    .line 298
    .line 299
    .line 300
    invoke-virtual {v6, v8}, Lxl0/f;->c(Lay0/k;)Lyy0/m1;

    .line 301
    .line 302
    .line 303
    move-result-object v4

    .line 304
    new-instance v6, Lk20/a;

    .line 305
    .line 306
    const/16 v8, 0xe

    .line 307
    .line 308
    invoke-direct {v6, v5, v7, v8}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 309
    .line 310
    .line 311
    invoke-static {v6, v4}, Lbb/j0;->f(Lay0/n;Lyy0/i;)Lne0/n;

    .line 312
    .line 313
    .line 314
    move-result-object v4

    .line 315
    invoke-static {v4}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 316
    .line 317
    .line 318
    move-result-object v4

    .line 319
    if-ne v4, v1, :cond_11

    .line 320
    .line 321
    goto :goto_7

    .line 322
    :cond_11
    :goto_4
    check-cast v4, Lyy0/i;

    .line 323
    .line 324
    :goto_5
    new-instance v5, Luk0/c;

    .line 325
    .line 326
    const/4 v6, 0x0

    .line 327
    invoke-direct {v5, v4, v2, v6}, Luk0/c;-><init>(Lyy0/i;Ljava/lang/String;I)V

    .line 328
    .line 329
    .line 330
    goto :goto_6

    .line 331
    :cond_12
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 332
    .line 333
    new-instance v1, Ljava/lang/StringBuilder;

    .line 334
    .line 335
    const-string v2, "Unsupported type: "

    .line 336
    .line 337
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 338
    .line 339
    .line 340
    invoke-virtual {v1, v8}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 341
    .line 342
    .line 343
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 344
    .line 345
    .line 346
    move-result-object v1

    .line 347
    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 348
    .line 349
    .line 350
    throw v0

    .line 351
    :cond_13
    instance-of v4, v2, Lne0/c;

    .line 352
    .line 353
    if-eqz v4, :cond_15

    .line 354
    .line 355
    new-instance v5, Lyy0/m;

    .line 356
    .line 357
    const/4 v4, 0x0

    .line 358
    invoke-direct {v5, v2, v4}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 359
    .line 360
    .line 361
    :goto_6
    iput-object v7, v0, Luk0/a;->e:Lyy0/j;

    .line 362
    .line 363
    iput-object v7, v0, Luk0/a;->f:Ljava/lang/Object;

    .line 364
    .line 365
    iput-object v7, v0, Luk0/a;->g:Lyy0/j;

    .line 366
    .line 367
    iput-object v7, v0, Luk0/a;->j:Lvk0/j0;

    .line 368
    .line 369
    iput-object v7, v0, Luk0/a;->k:Ljava/lang/String;

    .line 370
    .line 371
    iput v3, v0, Luk0/a;->d:I

    .line 372
    .line 373
    invoke-static {v9, v5, v0}, Lyy0/u;->q(Lyy0/j;Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 374
    .line 375
    .line 376
    move-result-object v0

    .line 377
    if-ne v0, v1, :cond_14

    .line 378
    .line 379
    :goto_7
    return-object v1

    .line 380
    :cond_14
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 381
    .line 382
    return-object v0

    .line 383
    :cond_15
    new-instance v0, La8/r0;

    .line 384
    .line 385
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 386
    .line 387
    .line 388
    throw v0
.end method
