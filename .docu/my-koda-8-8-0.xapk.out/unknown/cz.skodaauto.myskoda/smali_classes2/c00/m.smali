.class public final Lc00/m;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc00/p;


# direct methods
.method public synthetic constructor <init>(Lc00/p;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc00/m;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc00/m;->e:Lc00/p;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lc00/m;->d:I

    .line 4
    .line 5
    packed-switch v1, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    move-object/from16 v1, p1

    .line 9
    .line 10
    check-cast v1, Llx0/l;

    .line 11
    .line 12
    iget-object v2, v1, Llx0/l;->d:Ljava/lang/Object;

    .line 13
    .line 14
    check-cast v2, Lne0/s;

    .line 15
    .line 16
    iget-object v1, v1, Llx0/l;->e:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast v1, Ljava/util/List;

    .line 19
    .line 20
    iget-object v0, v0, Lc00/m;->e:Lc00/p;

    .line 21
    .line 22
    iget-object v3, v0, Lc00/p;->l:Lij0/a;

    .line 23
    .line 24
    sget-object v4, Lne0/d;->a:Lne0/d;

    .line 25
    .line 26
    invoke-static {v2, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 27
    .line 28
    .line 29
    move-result v4

    .line 30
    if-eqz v4, :cond_0

    .line 31
    .line 32
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 33
    .line 34
    .line 35
    move-result-object v2

    .line 36
    move-object v3, v2

    .line 37
    check-cast v3, Lc00/n;

    .line 38
    .line 39
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 40
    .line 41
    .line 42
    move-result-object v2

    .line 43
    check-cast v2, Lc00/n;

    .line 44
    .line 45
    iget-boolean v9, v2, Lc00/n;->g:Z

    .line 46
    .line 47
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    check-cast v2, Lc00/n;

    .line 52
    .line 53
    iget-boolean v10, v2, Lc00/n;->h:Z

    .line 54
    .line 55
    const/4 v14, 0x0

    .line 56
    const/16 v15, 0xc3f

    .line 57
    .line 58
    const/4 v4, 0x0

    .line 59
    const/4 v5, 0x0

    .line 60
    const/4 v6, 0x0

    .line 61
    const/4 v7, 0x0

    .line 62
    const/4 v8, 0x0

    .line 63
    const/4 v11, 0x0

    .line 64
    const/4 v12, 0x0

    .line 65
    const/4 v13, 0x0

    .line 66
    invoke-static/range {v3 .. v15}, Lc00/n;->a(Lc00/n;ZLjava/lang/String;Ljava/lang/String;ZLlf0/i;ZZLqr0/q;Lmb0/i;Ljava/lang/Boolean;ZI)Lc00/n;

    .line 67
    .line 68
    .line 69
    move-result-object v2

    .line 70
    goto/16 :goto_3

    .line 71
    .line 72
    :cond_0
    instance-of v4, v2, Lne0/e;

    .line 73
    .line 74
    if-eqz v4, :cond_7

    .line 75
    .line 76
    check-cast v2, Lne0/e;

    .line 77
    .line 78
    iget-object v2, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast v2, Lmb0/f;

    .line 81
    .line 82
    iget-object v4, v2, Lmb0/f;->a:Lmb0/e;

    .line 83
    .line 84
    iget-object v5, v2, Lmb0/f;->e:Lqr0/q;

    .line 85
    .line 86
    invoke-static {v4}, Ljp/a1;->c(Lmb0/e;)Z

    .line 87
    .line 88
    .line 89
    move-result v4

    .line 90
    if-eqz v4, :cond_6

    .line 91
    .line 92
    const-string v4, "stringResource"

    .line 93
    .line 94
    const-string v6, "<this>"

    .line 95
    .line 96
    const/4 v7, 0x0

    .line 97
    if-eqz v5, :cond_5

    .line 98
    .line 99
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 100
    .line 101
    .line 102
    move-result-object v8

    .line 103
    move-object v9, v8

    .line 104
    check-cast v9, Lc00/n;

    .line 105
    .line 106
    invoke-static {v9, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 107
    .line 108
    .line 109
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 110
    .line 111
    .line 112
    iget-object v4, v2, Lmb0/f;->j:Lmb0/i;

    .line 113
    .line 114
    iget-object v6, v2, Lmb0/f;->e:Lqr0/q;

    .line 115
    .line 116
    iget-object v8, v2, Lmb0/f;->a:Lmb0/e;

    .line 117
    .line 118
    invoke-static {v8}, Ljp/a1;->b(Lmb0/e;)Z

    .line 119
    .line 120
    .line 121
    move-result v10

    .line 122
    invoke-static {v5, v3}, Lkp/p6;->b(Lqr0/q;Lij0/a;)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object v11

    .line 126
    invoke-static {v2}, Ljp/vb;->e(Lmb0/f;)Z

    .line 127
    .line 128
    .line 129
    move-result v5

    .line 130
    if-eqz v5, :cond_1

    .line 131
    .line 132
    new-array v5, v7, [Ljava/lang/Object;

    .line 133
    .line 134
    check-cast v3, Ljj0/f;

    .line 135
    .line 136
    const v12, 0x7f12007c

    .line 137
    .line 138
    .line 139
    invoke-virtual {v3, v12, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 140
    .line 141
    .line 142
    move-result-object v3

    .line 143
    :goto_0
    move-object v12, v3

    .line 144
    goto :goto_1

    .line 145
    :cond_1
    invoke-static {v2, v3}, Ljp/vb;->b(Lmb0/f;Lij0/a;)Ljava/lang/String;

    .line 146
    .line 147
    .line 148
    move-result-object v3

    .line 149
    goto :goto_0

    .line 150
    :goto_1
    invoke-static {v2}, Ljp/vb;->e(Lmb0/f;)Z

    .line 151
    .line 152
    .line 153
    move-result v3

    .line 154
    const/4 v5, 0x1

    .line 155
    if-nez v3, :cond_2

    .line 156
    .line 157
    invoke-static {v8}, Ljp/a1;->c(Lmb0/e;)Z

    .line 158
    .line 159
    .line 160
    move-result v3

    .line 161
    if-eqz v3, :cond_2

    .line 162
    .line 163
    move v13, v5

    .line 164
    goto :goto_2

    .line 165
    :cond_2
    move v13, v7

    .line 166
    :goto_2
    sget-object v14, Llf0/i;->j:Llf0/i;

    .line 167
    .line 168
    iget-object v3, v2, Lmb0/f;->k:Lmb0/g;

    .line 169
    .line 170
    sget-object v8, Lmb0/g;->d:Lmb0/g;

    .line 171
    .line 172
    if-ne v3, v8, :cond_3

    .line 173
    .line 174
    iget-object v2, v2, Lmb0/f;->f:Ljava/lang/Boolean;

    .line 175
    .line 176
    sget-object v3, Ljava/lang/Boolean;->FALSE:Ljava/lang/Boolean;

    .line 177
    .line 178
    invoke-static {v2, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    move-result v2

    .line 182
    if-nez v2, :cond_4

    .line 183
    .line 184
    :cond_3
    move v7, v5

    .line 185
    :cond_4
    invoke-static {v7}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 186
    .line 187
    .line 188
    move-result-object v19

    .line 189
    const/16 v20, 0x0

    .line 190
    .line 191
    const/16 v21, 0x8c0

    .line 192
    .line 193
    const/4 v15, 0x0

    .line 194
    const/16 v16, 0x0

    .line 195
    .line 196
    move-object/from16 v18, v4

    .line 197
    .line 198
    move-object/from16 v17, v6

    .line 199
    .line 200
    invoke-static/range {v9 .. v21}, Lc00/n;->a(Lc00/n;ZLjava/lang/String;Ljava/lang/String;ZLlf0/i;ZZLqr0/q;Lmb0/i;Ljava/lang/Boolean;ZI)Lc00/n;

    .line 201
    .line 202
    .line 203
    move-result-object v2

    .line 204
    goto :goto_3

    .line 205
    :cond_5
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 206
    .line 207
    .line 208
    move-result-object v2

    .line 209
    move-object v8, v2

    .line 210
    check-cast v8, Lc00/n;

    .line 211
    .line 212
    invoke-static {v8, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    new-array v2, v7, [Ljava/lang/Object;

    .line 219
    .line 220
    check-cast v3, Ljj0/f;

    .line 221
    .line 222
    const v4, 0x7f1201aa

    .line 223
    .line 224
    .line 225
    invoke-virtual {v3, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 226
    .line 227
    .line 228
    move-result-object v10

    .line 229
    const v2, 0x7f120080

    .line 230
    .line 231
    .line 232
    new-array v4, v7, [Ljava/lang/Object;

    .line 233
    .line 234
    invoke-virtual {v3, v2, v4}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 235
    .line 236
    .line 237
    move-result-object v11

    .line 238
    sget-object v13, Llf0/i;->j:Llf0/i;

    .line 239
    .line 240
    const/16 v19, 0x0

    .line 241
    .line 242
    const/16 v20, 0xcc0

    .line 243
    .line 244
    const/4 v9, 0x1

    .line 245
    const/4 v12, 0x0

    .line 246
    const/4 v14, 0x0

    .line 247
    const/4 v15, 0x0

    .line 248
    const/16 v16, 0x0

    .line 249
    .line 250
    const/16 v17, 0x0

    .line 251
    .line 252
    const/16 v18, 0x0

    .line 253
    .line 254
    invoke-static/range {v8 .. v20}, Lc00/n;->a(Lc00/n;ZLjava/lang/String;Ljava/lang/String;ZLlf0/i;ZZLqr0/q;Lmb0/i;Ljava/lang/Boolean;ZI)Lc00/n;

    .line 255
    .line 256
    .line 257
    move-result-object v2

    .line 258
    goto :goto_3

    .line 259
    :cond_6
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 260
    .line 261
    .line 262
    move-result-object v2

    .line 263
    check-cast v2, Lc00/n;

    .line 264
    .line 265
    invoke-static {v2, v3}, Ljp/xb;->w(Lc00/n;Lij0/a;)Lc00/n;

    .line 266
    .line 267
    .line 268
    move-result-object v2

    .line 269
    goto :goto_3

    .line 270
    :cond_7
    instance-of v2, v2, Lne0/c;

    .line 271
    .line 272
    if-eqz v2, :cond_a

    .line 273
    .line 274
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 275
    .line 276
    .line 277
    move-result-object v2

    .line 278
    check-cast v2, Lc00/n;

    .line 279
    .line 280
    iget-boolean v2, v2, Lc00/n;->e:Z

    .line 281
    .line 282
    if-nez v2, :cond_8

    .line 283
    .line 284
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 285
    .line 286
    .line 287
    move-result-object v2

    .line 288
    check-cast v2, Lc00/n;

    .line 289
    .line 290
    goto :goto_3

    .line 291
    :cond_8
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 292
    .line 293
    .line 294
    move-result-object v2

    .line 295
    check-cast v2, Lc00/n;

    .line 296
    .line 297
    invoke-static {v2, v3}, Ljp/xb;->w(Lc00/n;Lij0/a;)Lc00/n;

    .line 298
    .line 299
    .line 300
    move-result-object v2

    .line 301
    :goto_3
    invoke-virtual {v0, v2}, Lql0/j;->g(Lql0/h;)V

    .line 302
    .line 303
    .line 304
    check-cast v1, Ljava/lang/Iterable;

    .line 305
    .line 306
    invoke-interface {v1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 307
    .line 308
    .line 309
    move-result-object v1

    .line 310
    :goto_4
    invoke-interface {v1}, Ljava/util/Iterator;->hasNext()Z

    .line 311
    .line 312
    .line 313
    move-result v2

    .line 314
    if-eqz v2, :cond_9

    .line 315
    .line 316
    invoke-interface {v1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object v2

    .line 320
    check-cast v2, Lcn0/c;

    .line 321
    .line 322
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 323
    .line 324
    .line 325
    move-result-object v3

    .line 326
    new-instance v4, La7/o;

    .line 327
    .line 328
    const/16 v5, 0xe

    .line 329
    .line 330
    const/4 v6, 0x0

    .line 331
    invoke-direct {v4, v5, v2, v0, v6}, La7/o;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 332
    .line 333
    .line 334
    const/4 v2, 0x3

    .line 335
    invoke-static {v3, v6, v6, v4, v2}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 336
    .line 337
    .line 338
    goto :goto_4

    .line 339
    :cond_9
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 340
    .line 341
    return-object v0

    .line 342
    :cond_a
    new-instance v0, La8/r0;

    .line 343
    .line 344
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 345
    .line 346
    .line 347
    throw v0

    .line 348
    :pswitch_0
    move-object/from16 v1, p1

    .line 349
    .line 350
    check-cast v1, Lss0/j0;

    .line 351
    .line 352
    new-instance v1, Lc00/n;

    .line 353
    .line 354
    const/4 v2, 0x0

    .line 355
    const/16 v3, 0xfff

    .line 356
    .line 357
    invoke-direct {v1, v3, v2, v2}, Lc00/n;-><init>(ILjava/lang/String;Llf0/i;)V

    .line 358
    .line 359
    .line 360
    iget-object v0, v0, Lc00/m;->e:Lc00/p;

    .line 361
    .line 362
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 363
    .line 364
    .line 365
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 366
    .line 367
    return-object v0

    .line 368
    :pswitch_1
    move-object/from16 v1, p1

    .line 369
    .line 370
    check-cast v1, Ljava/lang/Boolean;

    .line 371
    .line 372
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 373
    .line 374
    .line 375
    move-result v9

    .line 376
    iget-object v0, v0, Lc00/m;->e:Lc00/p;

    .line 377
    .line 378
    invoke-virtual {v0}, Lql0/j;->a()Lql0/h;

    .line 379
    .line 380
    .line 381
    move-result-object v1

    .line 382
    move-object v2, v1

    .line 383
    check-cast v2, Lc00/n;

    .line 384
    .line 385
    const/4 v13, 0x0

    .line 386
    const/16 v14, 0xf7f

    .line 387
    .line 388
    const/4 v3, 0x0

    .line 389
    const/4 v4, 0x0

    .line 390
    const/4 v5, 0x0

    .line 391
    const/4 v6, 0x0

    .line 392
    const/4 v7, 0x0

    .line 393
    const/4 v8, 0x0

    .line 394
    const/4 v10, 0x0

    .line 395
    const/4 v11, 0x0

    .line 396
    const/4 v12, 0x0

    .line 397
    invoke-static/range {v2 .. v14}, Lc00/n;->a(Lc00/n;ZLjava/lang/String;Ljava/lang/String;ZLlf0/i;ZZLqr0/q;Lmb0/i;Ljava/lang/Boolean;ZI)Lc00/n;

    .line 398
    .line 399
    .line 400
    move-result-object v1

    .line 401
    invoke-virtual {v0, v1}, Lql0/j;->g(Lql0/h;)V

    .line 402
    .line 403
    .line 404
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 405
    .line 406
    return-object v0

    .line 407
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
