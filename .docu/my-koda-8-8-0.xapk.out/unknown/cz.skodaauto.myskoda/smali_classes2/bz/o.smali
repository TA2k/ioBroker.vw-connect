.class public final Lbz/o;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lbz/r;


# direct methods
.method public synthetic constructor <init>(Lbz/r;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lbz/o;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lbz/o;->f:Lbz/r;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 1

    .line 1
    iget p1, p0, Lbz/o;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lbz/o;

    .line 7
    .line 8
    iget-object p0, p0, Lbz/o;->f:Lbz/r;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lbz/o;-><init>(Lbz/r;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lbz/o;

    .line 16
    .line 17
    iget-object p0, p0, Lbz/o;->f:Lbz/r;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lbz/o;-><init>(Lbz/r;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lbz/o;

    .line 25
    .line 26
    iget-object p0, p0, Lbz/o;->f:Lbz/r;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lbz/o;-><init>(Lbz/r;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lbz/o;->d:I

    .line 2
    .line 3
    check-cast p1, Lvy0/b0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lbz/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lbz/o;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lbz/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lbz/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lbz/o;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lbz/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lbz/o;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lbz/o;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lbz/o;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lbz/o;->d:I

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const-string v3, "call to \'resume\' before \'invoke\' with coroutine"

    .line 7
    .line 8
    iget-object v4, v0, Lbz/o;->f:Lbz/r;

    .line 9
    .line 10
    const/4 v5, 0x1

    .line 11
    sget-object v6, Llx0/b0;->a:Llx0/b0;

    .line 12
    .line 13
    packed-switch v1, :pswitch_data_0

    .line 14
    .line 15
    .line 16
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 17
    .line 18
    iget v2, v0, Lbz/o;->e:I

    .line 19
    .line 20
    const/4 v7, 0x2

    .line 21
    if-eqz v2, :cond_2

    .line 22
    .line 23
    if-eq v2, v5, :cond_1

    .line 24
    .line 25
    if-ne v2, v7, :cond_0

    .line 26
    .line 27
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    goto :goto_2

    .line 31
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw v0

    .line 37
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 38
    .line 39
    .line 40
    goto :goto_0

    .line 41
    :cond_2
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    iput v5, v0, Lbz/o;->e:I

    .line 45
    .line 46
    invoke-static {v4, v0}, Lbz/r;->h(Lbz/r;Lrx0/i;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    move-result-object v2

    .line 50
    if-ne v2, v1, :cond_3

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_3
    :goto_0
    iget-object v2, v4, Lbz/r;->n:Lzy/o;

    .line 54
    .line 55
    iput v7, v0, Lbz/o;->e:I

    .line 56
    .line 57
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v2, v0}, Lzy/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v0

    .line 64
    if-ne v0, v1, :cond_4

    .line 65
    .line 66
    :goto_1
    move-object v6, v1

    .line 67
    goto :goto_3

    .line 68
    :cond_4
    :goto_2
    iget-object v0, v4, Lbz/r;->l:Lzy/v;

    .line 69
    .line 70
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    :goto_3
    return-object v6

    .line 74
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 75
    .line 76
    iget v7, v0, Lbz/o;->e:I

    .line 77
    .line 78
    if-eqz v7, :cond_6

    .line 79
    .line 80
    if-ne v7, v5, :cond_5

    .line 81
    .line 82
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    goto :goto_4

    .line 86
    :cond_5
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 87
    .line 88
    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 89
    .line 90
    .line 91
    throw v0

    .line 92
    :cond_6
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 93
    .line 94
    .line 95
    iput v5, v0, Lbz/o;->e:I

    .line 96
    .line 97
    invoke-static {v4, v0}, Lbz/r;->h(Lbz/r;Lrx0/i;)Ljava/lang/Object;

    .line 98
    .line 99
    .line 100
    move-result-object v0

    .line 101
    if-ne v0, v1, :cond_7

    .line 102
    .line 103
    move-object v6, v1

    .line 104
    goto :goto_5

    .line 105
    :cond_7
    :goto_4
    iget-object v0, v4, Lbz/r;->m:Lzy/q;

    .line 106
    .line 107
    invoke-virtual {v0, v2}, Lzy/q;->a(Z)V

    .line 108
    .line 109
    .line 110
    iget-object v0, v4, Lbz/r;->j:Ltr0/b;

    .line 111
    .line 112
    invoke-static {v0}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    :goto_5
    return-object v6

    .line 116
    :pswitch_1
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 117
    .line 118
    iget v7, v0, Lbz/o;->e:I

    .line 119
    .line 120
    if-eqz v7, :cond_9

    .line 121
    .line 122
    if-ne v7, v5, :cond_8

    .line 123
    .line 124
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 125
    .line 126
    .line 127
    move-object/from16 v7, p1

    .line 128
    .line 129
    goto :goto_6

    .line 130
    :cond_8
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 131
    .line 132
    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 133
    .line 134
    .line 135
    throw v0

    .line 136
    :cond_9
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 137
    .line 138
    .line 139
    iget-object v3, v4, Lbz/r;->i:Lzy/j;

    .line 140
    .line 141
    iput v5, v0, Lbz/o;->e:I

    .line 142
    .line 143
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 144
    .line 145
    .line 146
    iget-object v0, v3, Lzy/j;->a:Lxy/e;

    .line 147
    .line 148
    new-instance v7, Laz/i;

    .line 149
    .line 150
    iget-object v8, v0, Lxy/e;->b:Laz/d;

    .line 151
    .line 152
    iget-object v9, v0, Lxy/e;->c:Laz/d;

    .line 153
    .line 154
    iget-object v10, v0, Lxy/e;->d:Ljava/util/ArrayList;

    .line 155
    .line 156
    iget v11, v0, Lxy/e;->h:I

    .line 157
    .line 158
    iget-object v12, v0, Lxy/e;->e:Ljava/util/ArrayList;

    .line 159
    .line 160
    iget-object v13, v0, Lxy/e;->f:Laz/h;

    .line 161
    .line 162
    iget-boolean v14, v0, Lxy/e;->g:Z

    .line 163
    .line 164
    iget-boolean v15, v0, Lxy/e;->i:Z

    .line 165
    .line 166
    invoke-direct/range {v7 .. v15}, Laz/i;-><init>(Laz/d;Laz/d;Ljava/util/List;ILjava/util/List;Laz/h;ZZ)V

    .line 167
    .line 168
    .line 169
    if-ne v7, v1, :cond_a

    .line 170
    .line 171
    move-object v6, v1

    .line 172
    goto/16 :goto_e

    .line 173
    .line 174
    :cond_a
    :goto_6
    check-cast v7, Laz/i;

    .line 175
    .line 176
    invoke-virtual {v4}, Lql0/j;->a()Lql0/h;

    .line 177
    .line 178
    .line 179
    move-result-object v0

    .line 180
    check-cast v0, Lbz/q;

    .line 181
    .line 182
    sget-object v1, Laz/g;->e:Lsx0/b;

    .line 183
    .line 184
    new-instance v9, Ljava/util/ArrayList;

    .line 185
    .line 186
    const/16 v3, 0xa

    .line 187
    .line 188
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 189
    .line 190
    .line 191
    move-result v8

    .line 192
    invoke-direct {v9, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 193
    .line 194
    .line 195
    new-instance v8, Landroidx/collection/d1;

    .line 196
    .line 197
    const/4 v10, 0x6

    .line 198
    invoke-direct {v8, v1, v10}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 199
    .line 200
    .line 201
    :goto_7
    invoke-virtual {v8}, Landroidx/collection/d1;->hasNext()Z

    .line 202
    .line 203
    .line 204
    move-result v1

    .line 205
    if-eqz v1, :cond_b

    .line 206
    .line 207
    invoke-virtual {v8}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v1

    .line 211
    check-cast v1, Laz/g;

    .line 212
    .line 213
    invoke-static {v1}, Ljp/lb;->b(Laz/g;)I

    .line 214
    .line 215
    .line 216
    move-result v1

    .line 217
    new-instance v11, Ljava/lang/Integer;

    .line 218
    .line 219
    invoke-direct {v11, v1}, Ljava/lang/Integer;-><init>(I)V

    .line 220
    .line 221
    .line 222
    invoke-virtual {v9, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    goto :goto_7

    .line 226
    :cond_b
    sget-object v1, Laz/h;->k:Lsx0/b;

    .line 227
    .line 228
    new-instance v11, Ljava/util/ArrayList;

    .line 229
    .line 230
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 231
    .line 232
    .line 233
    move-result v8

    .line 234
    invoke-direct {v11, v8}, Ljava/util/ArrayList;-><init>(I)V

    .line 235
    .line 236
    .line 237
    new-instance v8, Landroidx/collection/d1;

    .line 238
    .line 239
    invoke-direct {v8, v1, v10}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 240
    .line 241
    .line 242
    :goto_8
    invoke-virtual {v8}, Landroidx/collection/d1;->hasNext()Z

    .line 243
    .line 244
    .line 245
    move-result v1

    .line 246
    if-eqz v1, :cond_c

    .line 247
    .line 248
    invoke-virtual {v8}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 249
    .line 250
    .line 251
    move-result-object v1

    .line 252
    check-cast v1, Laz/h;

    .line 253
    .line 254
    invoke-static {v1}, Ljp/mb;->c(Laz/h;)I

    .line 255
    .line 256
    .line 257
    move-result v1

    .line 258
    new-instance v12, Ljava/lang/Integer;

    .line 259
    .line 260
    invoke-direct {v12, v1}, Ljava/lang/Integer;-><init>(I)V

    .line 261
    .line 262
    .line 263
    invoke-virtual {v11, v12}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 264
    .line 265
    .line 266
    goto :goto_8

    .line 267
    :cond_c
    sget-object v1, Laz/f;->e:Lsx0/b;

    .line 268
    .line 269
    new-instance v13, Ljava/util/ArrayList;

    .line 270
    .line 271
    invoke-static {v1, v3}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 272
    .line 273
    .line 274
    move-result v3

    .line 275
    invoke-direct {v13, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 276
    .line 277
    .line 278
    new-instance v3, Landroidx/collection/d1;

    .line 279
    .line 280
    invoke-direct {v3, v1, v10}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 281
    .line 282
    .line 283
    :goto_9
    invoke-virtual {v3}, Landroidx/collection/d1;->hasNext()Z

    .line 284
    .line 285
    .line 286
    move-result v1

    .line 287
    if-eqz v1, :cond_11

    .line 288
    .line 289
    invoke-virtual {v3}, Landroidx/collection/d1;->next()Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v1

    .line 293
    check-cast v1, Laz/f;

    .line 294
    .line 295
    new-instance v8, Lbz/p;

    .line 296
    .line 297
    const-string v10, "<this>"

    .line 298
    .line 299
    invoke-static {v1, v10}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 300
    .line 301
    .line 302
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 303
    .line 304
    .line 305
    move-result v10

    .line 306
    if-eqz v10, :cond_e

    .line 307
    .line 308
    if-ne v10, v5, :cond_d

    .line 309
    .line 310
    const v10, 0x7f120070

    .line 311
    .line 312
    .line 313
    goto :goto_a

    .line 314
    :cond_d
    new-instance v0, La8/r0;

    .line 315
    .line 316
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 317
    .line 318
    .line 319
    throw v0

    .line 320
    :cond_e
    const v10, 0x7f120066

    .line 321
    .line 322
    .line 323
    :goto_a
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 324
    .line 325
    .line 326
    move-result v1

    .line 327
    if-eqz v1, :cond_10

    .line 328
    .line 329
    if-ne v1, v5, :cond_f

    .line 330
    .line 331
    const v1, 0x7f080522

    .line 332
    .line 333
    .line 334
    goto :goto_b

    .line 335
    :cond_f
    new-instance v0, La8/r0;

    .line 336
    .line 337
    invoke-direct {v0}, Ljava/lang/RuntimeException;-><init>()V

    .line 338
    .line 339
    .line 340
    throw v0

    .line 341
    :cond_10
    const v1, 0x7f080451

    .line 342
    .line 343
    .line 344
    :goto_b
    invoke-direct {v8, v10, v1}, Lbz/p;-><init>(II)V

    .line 345
    .line 346
    .line 347
    invoke-virtual {v13, v8}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 348
    .line 349
    .line 350
    goto :goto_9

    .line 351
    :cond_11
    iget-object v1, v7, Laz/i;->f:Laz/h;

    .line 352
    .line 353
    iget-boolean v3, v7, Laz/i;->h:Z

    .line 354
    .line 355
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 356
    .line 357
    .line 358
    move-result v12

    .line 359
    iget v10, v7, Laz/i;->d:I

    .line 360
    .line 361
    iget-boolean v1, v7, Laz/i;->g:Z

    .line 362
    .line 363
    if-eqz v1, :cond_12

    .line 364
    .line 365
    if-eqz v3, :cond_12

    .line 366
    .line 367
    sget-object v1, Laz/f;->d:[Laz/f;

    .line 368
    .line 369
    new-instance v1, Ljava/lang/Integer;

    .line 370
    .line 371
    invoke-direct {v1, v2}, Ljava/lang/Integer;-><init>(I)V

    .line 372
    .line 373
    .line 374
    new-instance v2, Ljava/lang/Integer;

    .line 375
    .line 376
    invoke-direct {v2, v5}, Ljava/lang/Integer;-><init>(I)V

    .line 377
    .line 378
    .line 379
    filled-new-array {v1, v2}, [Ljava/lang/Integer;

    .line 380
    .line 381
    .line 382
    move-result-object v1

    .line 383
    invoke-static {v1}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 384
    .line 385
    .line 386
    move-result-object v1

    .line 387
    :goto_c
    move-object v14, v1

    .line 388
    goto :goto_d

    .line 389
    :cond_12
    if-eqz v1, :cond_13

    .line 390
    .line 391
    sget-object v1, Laz/f;->d:[Laz/f;

    .line 392
    .line 393
    new-instance v1, Ljava/lang/Integer;

    .line 394
    .line 395
    invoke-direct {v1, v2}, Ljava/lang/Integer;-><init>(I)V

    .line 396
    .line 397
    .line 398
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 399
    .line 400
    .line 401
    move-result-object v1

    .line 402
    goto :goto_c

    .line 403
    :cond_13
    if-eqz v3, :cond_14

    .line 404
    .line 405
    sget-object v1, Laz/f;->d:[Laz/f;

    .line 406
    .line 407
    new-instance v1, Ljava/lang/Integer;

    .line 408
    .line 409
    invoke-direct {v1, v5}, Ljava/lang/Integer;-><init>(I)V

    .line 410
    .line 411
    .line 412
    invoke-static {v1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 413
    .line 414
    .line 415
    move-result-object v1

    .line 416
    goto :goto_c

    .line 417
    :cond_14
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 418
    .line 419
    goto :goto_c

    .line 420
    :goto_d
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 421
    .line 422
    .line 423
    new-instance v8, Lbz/q;

    .line 424
    .line 425
    invoke-direct/range {v8 .. v14}, Lbz/q;-><init>(Ljava/util/List;ILjava/util/List;ILjava/util/List;Ljava/util/List;)V

    .line 426
    .line 427
    .line 428
    invoke-virtual {v4, v8}, Lql0/j;->g(Lql0/h;)V

    .line 429
    .line 430
    .line 431
    :goto_e
    return-object v6

    .line 432
    nop

    .line 433
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
