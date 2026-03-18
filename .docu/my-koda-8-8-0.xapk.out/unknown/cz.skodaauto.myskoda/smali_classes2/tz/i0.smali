.class public final Ltz/i0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public e:Ljava/util/Iterator;

.field public f:I

.field public g:I

.field public synthetic h:Lne0/s;

.field public synthetic i:Ljava/util/List;

.field public j:Lql0/j;

.field public final synthetic k:Lql0/j;


# direct methods
.method public synthetic constructor <init>(Lql0/j;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ltz/i0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ltz/i0;->k:Lql0/j;

    .line 4
    .line 5
    const/4 p1, 0x3

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Ltz/i0;->d:I

    .line 2
    .line 3
    check-cast p1, Lne0/s;

    .line 4
    .line 5
    check-cast p2, Ljava/util/List;

    .line 6
    .line 7
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 8
    .line 9
    packed-switch v0, :pswitch_data_0

    .line 10
    .line 11
    .line 12
    new-instance v0, Ltz/i0;

    .line 13
    .line 14
    iget-object p0, p0, Ltz/i0;->k:Lql0/j;

    .line 15
    .line 16
    check-cast p0, Ltz/p2;

    .line 17
    .line 18
    const/4 v1, 0x1

    .line 19
    invoke-direct {v0, p0, p3, v1}, Ltz/i0;-><init>(Lql0/j;Lkotlin/coroutines/Continuation;I)V

    .line 20
    .line 21
    .line 22
    iput-object p1, v0, Ltz/i0;->h:Lne0/s;

    .line 23
    .line 24
    check-cast p2, Ljava/util/List;

    .line 25
    .line 26
    iput-object p2, v0, Ltz/i0;->i:Ljava/util/List;

    .line 27
    .line 28
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    invoke-virtual {v0, p0}, Ltz/i0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object p0

    .line 34
    return-object p0

    .line 35
    :pswitch_0
    new-instance v0, Ltz/i0;

    .line 36
    .line 37
    iget-object p0, p0, Ltz/i0;->k:Lql0/j;

    .line 38
    .line 39
    check-cast p0, Ltz/n0;

    .line 40
    .line 41
    const/4 v1, 0x0

    .line 42
    invoke-direct {v0, p0, p3, v1}, Ltz/i0;-><init>(Lql0/j;Lkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    iput-object p1, v0, Ltz/i0;->h:Lne0/s;

    .line 46
    .line 47
    check-cast p2, Ljava/util/List;

    .line 48
    .line 49
    iput-object p2, v0, Ltz/i0;->i:Ljava/util/List;

    .line 50
    .line 51
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 52
    .line 53
    invoke-virtual {v0, p0}, Ltz/i0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v9, p0

    .line 2
    .line 3
    iget v0, v9, Ltz/i0;->d:I

    .line 4
    .line 5
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 6
    .line 7
    const/4 v11, 0x0

    .line 8
    const/4 v12, 0x1

    .line 9
    iget-object v2, v9, Ltz/i0;->k:Lql0/j;

    .line 10
    .line 11
    const/4 v3, 0x0

    .line 12
    sget-object v13, Llx0/b0;->a:Llx0/b0;

    .line 13
    .line 14
    packed-switch v0, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    check-cast v2, Ltz/p2;

    .line 18
    .line 19
    iget-object v0, v9, Ltz/i0;->h:Lne0/s;

    .line 20
    .line 21
    iget-object v4, v9, Ltz/i0;->i:Ljava/util/List;

    .line 22
    .line 23
    check-cast v4, Ljava/util/List;

    .line 24
    .line 25
    sget-object v14, Lqx0/a;->d:Lqx0/a;

    .line 26
    .line 27
    iget v5, v9, Ltz/i0;->g:I

    .line 28
    .line 29
    if-eqz v5, :cond_1

    .line 30
    .line 31
    if-ne v5, v12, :cond_0

    .line 32
    .line 33
    iget v0, v9, Ltz/i0;->f:I

    .line 34
    .line 35
    iget-object v1, v9, Ltz/i0;->e:Ljava/util/Iterator;

    .line 36
    .line 37
    iget-object v2, v9, Ltz/i0;->j:Lql0/j;

    .line 38
    .line 39
    check-cast v2, Ltz/p2;

    .line 40
    .line 41
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    move-object v15, v1

    .line 45
    move v1, v0

    .line 46
    move-object v0, v2

    .line 47
    goto :goto_0

    .line 48
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw v0

    .line 54
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    invoke-static {v2, v0}, Ltz/p2;->h(Ltz/p2;Lne0/s;)V

    .line 58
    .line 59
    .line 60
    check-cast v4, Ljava/lang/Iterable;

    .line 61
    .line 62
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    move-object v15, v0

    .line 67
    move-object v0, v2

    .line 68
    move v1, v3

    .line 69
    :goto_0
    invoke-interface {v15}, Ljava/util/Iterator;->hasNext()Z

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    if-eqz v2, :cond_5

    .line 74
    .line 75
    invoke-interface {v15}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v2

    .line 79
    check-cast v2, Lcn0/c;

    .line 80
    .line 81
    iput-object v11, v9, Ltz/i0;->h:Lne0/s;

    .line 82
    .line 83
    iput-object v11, v9, Ltz/i0;->i:Ljava/util/List;

    .line 84
    .line 85
    iput-object v0, v9, Ltz/i0;->j:Lql0/j;

    .line 86
    .line 87
    iput-object v15, v9, Ltz/i0;->e:Ljava/util/Iterator;

    .line 88
    .line 89
    iput v1, v9, Ltz/i0;->f:I

    .line 90
    .line 91
    iput v12, v9, Ltz/i0;->g:I

    .line 92
    .line 93
    if-eqz v2, :cond_3

    .line 94
    .line 95
    move v3, v1

    .line 96
    iget-object v1, v0, Ltz/p2;->n:Lrq0/f;

    .line 97
    .line 98
    iget-object v4, v0, Ltz/p2;->p:Ljn0/c;

    .line 99
    .line 100
    move v5, v3

    .line 101
    iget-object v3, v0, Ltz/p2;->q:Lyt0/b;

    .line 102
    .line 103
    move-object v6, v4

    .line 104
    iget-object v4, v0, Ltz/p2;->r:Lij0/a;

    .line 105
    .line 106
    move v7, v5

    .line 107
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    move-object v8, v6

    .line 112
    new-instance v6, Lt61/g;

    .line 113
    .line 114
    const/16 v10, 0x11

    .line 115
    .line 116
    invoke-direct {v6, v10, v0, v2}, Lt61/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    move-object v10, v0

    .line 120
    move-object v0, v2

    .line 121
    move-object v2, v8

    .line 122
    const/4 v8, 0x0

    .line 123
    move-object/from16 v16, v10

    .line 124
    .line 125
    const/16 v10, 0x1c0

    .line 126
    .line 127
    move/from16 v17, v7

    .line 128
    .line 129
    const/4 v7, 0x0

    .line 130
    invoke-static/range {v0 .. v10}, Ljp/fg;->f(Lcn0/c;Lrq0/f;Ljn0/c;Lyt0/b;Lij0/a;Lvy0/b0;Lay0/a;Lay0/k;Lay0/a;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v0

    .line 134
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 135
    .line 136
    if-ne v0, v1, :cond_2

    .line 137
    .line 138
    goto :goto_2

    .line 139
    :cond_2
    :goto_1
    move-object v0, v13

    .line 140
    goto :goto_2

    .line 141
    :cond_3
    move-object/from16 v16, v0

    .line 142
    .line 143
    move/from16 v17, v1

    .line 144
    .line 145
    invoke-virtual/range {v16 .. v16}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 146
    .line 147
    .line 148
    goto :goto_1

    .line 149
    :goto_2
    if-ne v0, v14, :cond_4

    .line 150
    .line 151
    move-object v13, v14

    .line 152
    goto :goto_3

    .line 153
    :cond_4
    move-object/from16 v0, v16

    .line 154
    .line 155
    move/from16 v1, v17

    .line 156
    .line 157
    goto :goto_0

    .line 158
    :cond_5
    :goto_3
    return-object v13

    .line 159
    :pswitch_0
    check-cast v2, Ltz/n0;

    .line 160
    .line 161
    iget-object v0, v9, Ltz/i0;->h:Lne0/s;

    .line 162
    .line 163
    iget-object v4, v9, Ltz/i0;->i:Ljava/util/List;

    .line 164
    .line 165
    check-cast v4, Ljava/util/List;

    .line 166
    .line 167
    sget-object v14, Lqx0/a;->d:Lqx0/a;

    .line 168
    .line 169
    iget v5, v9, Ltz/i0;->g:I

    .line 170
    .line 171
    const/4 v15, 0x2

    .line 172
    if-eqz v5, :cond_8

    .line 173
    .line 174
    if-eq v5, v12, :cond_7

    .line 175
    .line 176
    if-ne v5, v15, :cond_6

    .line 177
    .line 178
    iget v0, v9, Ltz/i0;->f:I

    .line 179
    .line 180
    iget-object v1, v9, Ltz/i0;->e:Ljava/util/Iterator;

    .line 181
    .line 182
    iget-object v2, v9, Ltz/i0;->j:Lql0/j;

    .line 183
    .line 184
    check-cast v2, Ltz/n0;

    .line 185
    .line 186
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    move-object v12, v1

    .line 190
    move v1, v0

    .line 191
    move-object v0, v2

    .line 192
    goto/16 :goto_b

    .line 193
    .line 194
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 195
    .line 196
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 197
    .line 198
    .line 199
    throw v0

    .line 200
    :cond_7
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 201
    .line 202
    .line 203
    goto :goto_6

    .line 204
    :cond_8
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 205
    .line 206
    .line 207
    instance-of v1, v0, Lne0/e;

    .line 208
    .line 209
    if-eqz v1, :cond_9

    .line 210
    .line 211
    move-object v1, v0

    .line 212
    check-cast v1, Lne0/e;

    .line 213
    .line 214
    goto :goto_4

    .line 215
    :cond_9
    move-object v1, v11

    .line 216
    :goto_4
    if-eqz v1, :cond_a

    .line 217
    .line 218
    iget-object v1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 219
    .line 220
    check-cast v1, Lrd0/b0;

    .line 221
    .line 222
    if-eqz v1, :cond_a

    .line 223
    .line 224
    iget-object v1, v1, Lrd0/b0;->b:Lrd0/t;

    .line 225
    .line 226
    if-eqz v1, :cond_a

    .line 227
    .line 228
    invoke-virtual {v1}, Lrd0/t;->a()Lrd0/r;

    .line 229
    .line 230
    .line 231
    move-result-object v1

    .line 232
    goto :goto_5

    .line 233
    :cond_a
    move-object v1, v11

    .line 234
    :goto_5
    iput-object v1, v2, Ltz/n0;->H:Lrd0/r;

    .line 235
    .line 236
    iput-object v11, v9, Ltz/i0;->h:Lne0/s;

    .line 237
    .line 238
    move-object v1, v4

    .line 239
    check-cast v1, Ljava/util/List;

    .line 240
    .line 241
    iput-object v1, v9, Ltz/i0;->i:Ljava/util/List;

    .line 242
    .line 243
    iput v12, v9, Ltz/i0;->g:I

    .line 244
    .line 245
    invoke-static {v2, v0, v9}, Ltz/n0;->h(Ltz/n0;Lne0/s;Lrx0/c;)Ljava/lang/Object;

    .line 246
    .line 247
    .line 248
    move-result-object v0

    .line 249
    if-ne v0, v14, :cond_b

    .line 250
    .line 251
    goto/16 :goto_a

    .line 252
    .line 253
    :cond_b
    :goto_6
    check-cast v4, Ljava/lang/Iterable;

    .line 254
    .line 255
    invoke-interface {v4}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 256
    .line 257
    .line 258
    move-result-object v0

    .line 259
    move-object v12, v0

    .line 260
    move-object v0, v2

    .line 261
    move v1, v3

    .line 262
    :goto_7
    invoke-interface {v12}, Ljava/util/Iterator;->hasNext()Z

    .line 263
    .line 264
    .line 265
    move-result v2

    .line 266
    if-eqz v2, :cond_f

    .line 267
    .line 268
    invoke-interface {v12}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 269
    .line 270
    .line 271
    move-result-object v2

    .line 272
    check-cast v2, Lcn0/c;

    .line 273
    .line 274
    iput-object v11, v9, Ltz/i0;->h:Lne0/s;

    .line 275
    .line 276
    iput-object v11, v9, Ltz/i0;->i:Ljava/util/List;

    .line 277
    .line 278
    iput-object v0, v9, Ltz/i0;->j:Lql0/j;

    .line 279
    .line 280
    iput-object v12, v9, Ltz/i0;->e:Ljava/util/Iterator;

    .line 281
    .line 282
    iput v1, v9, Ltz/i0;->f:I

    .line 283
    .line 284
    iput v15, v9, Ltz/i0;->g:I

    .line 285
    .line 286
    if-eqz v2, :cond_d

    .line 287
    .line 288
    move v3, v1

    .line 289
    iget-object v1, v0, Ltz/n0;->w:Lrq0/f;

    .line 290
    .line 291
    iget-object v4, v0, Ltz/n0;->y:Ljn0/c;

    .line 292
    .line 293
    move v5, v3

    .line 294
    iget-object v3, v0, Ltz/n0;->z:Lyt0/b;

    .line 295
    .line 296
    move-object v6, v4

    .line 297
    iget-object v4, v0, Ltz/n0;->v:Lij0/a;

    .line 298
    .line 299
    move v7, v5

    .line 300
    invoke-static {v0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 301
    .line 302
    .line 303
    move-result-object v5

    .line 304
    move-object v8, v6

    .line 305
    new-instance v6, Lt61/g;

    .line 306
    .line 307
    const/16 v10, 0x10

    .line 308
    .line 309
    invoke-direct {v6, v10, v0, v2}, Lt61/g;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 310
    .line 311
    .line 312
    move v10, v7

    .line 313
    new-instance v7, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;

    .line 314
    .line 315
    const/16 v11, 0x9

    .line 316
    .line 317
    invoke-direct {v7, v11, v0, v2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/vehicleplatform/meb/state/n;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 318
    .line 319
    .line 320
    move-object v11, v0

    .line 321
    move-object v0, v2

    .line 322
    move-object v2, v8

    .line 323
    const/4 v8, 0x0

    .line 324
    move/from16 v17, v10

    .line 325
    .line 326
    const/16 v10, 0x180

    .line 327
    .line 328
    invoke-static/range {v0 .. v10}, Ljp/fg;->f(Lcn0/c;Lrq0/f;Ljn0/c;Lyt0/b;Lij0/a;Lvy0/b0;Lay0/a;Lay0/k;Lay0/a;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object v0

    .line 332
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 333
    .line 334
    if-ne v0, v1, :cond_c

    .line 335
    .line 336
    goto :goto_9

    .line 337
    :cond_c
    :goto_8
    move-object v0, v13

    .line 338
    goto :goto_9

    .line 339
    :cond_d
    move-object v11, v0

    .line 340
    move/from16 v17, v1

    .line 341
    .line 342
    sget v0, Ltz/n0;->J:I

    .line 343
    .line 344
    invoke-virtual {v11}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 345
    .line 346
    .line 347
    goto :goto_8

    .line 348
    :goto_9
    if-ne v0, v14, :cond_e

    .line 349
    .line 350
    :goto_a
    move-object v13, v14

    .line 351
    goto :goto_c

    .line 352
    :cond_e
    move-object v0, v11

    .line 353
    move/from16 v1, v17

    .line 354
    .line 355
    :goto_b
    const/4 v11, 0x0

    .line 356
    move-object/from16 v9, p0

    .line 357
    .line 358
    goto :goto_7

    .line 359
    :cond_f
    :goto_c
    return-object v13

    .line 360
    nop

    .line 361
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
