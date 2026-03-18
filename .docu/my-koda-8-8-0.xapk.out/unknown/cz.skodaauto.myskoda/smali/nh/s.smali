.class public final Lnh/s;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lnh/u;


# direct methods
.method public synthetic constructor <init>(Lnh/u;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lnh/s;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lnh/s;->f:Lnh/u;

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
    iget p1, p0, Lnh/s;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lnh/s;

    .line 7
    .line 8
    iget-object p0, p0, Lnh/s;->f:Lnh/u;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lnh/s;-><init>(Lnh/u;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lnh/s;

    .line 16
    .line 17
    iget-object p0, p0, Lnh/s;->f:Lnh/u;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lnh/s;-><init>(Lnh/u;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lnh/s;->d:I

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
    invoke-virtual {p0, p1, p2}, Lnh/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lnh/s;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lnh/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lnh/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lnh/s;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lnh/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lnh/s;->d:I

    .line 4
    .line 5
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 6
    .line 7
    const-string v3, "call to \'resume\' before \'invoke\' with coroutine"

    .line 8
    .line 9
    iget-object v4, v0, Lnh/s;->f:Lnh/u;

    .line 10
    .line 11
    const-string v5, "<this>"

    .line 12
    .line 13
    const/4 v6, 0x1

    .line 14
    packed-switch v1, :pswitch_data_0

    .line 15
    .line 16
    .line 17
    iget-object v1, v4, Lnh/u;->f:Lyy0/c2;

    .line 18
    .line 19
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 20
    .line 21
    iget v8, v0, Lnh/s;->e:I

    .line 22
    .line 23
    if-eqz v8, :cond_1

    .line 24
    .line 25
    if-ne v8, v6, :cond_0

    .line 26
    .line 27
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    move-object/from16 v0, p1

    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 34
    .line 35
    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw v0

    .line 39
    :cond_1
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    sget-object v3, Lnh/w;->a:Lly0/n;

    .line 43
    .line 44
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    :cond_2
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    move-object v8, v3

    .line 52
    check-cast v8, Lnh/v;

    .line 53
    .line 54
    const/4 v15, 0x0

    .line 55
    const/16 v16, 0x3eb

    .line 56
    .line 57
    const/4 v9, 0x0

    .line 58
    const/4 v10, 0x0

    .line 59
    const/4 v11, 0x1

    .line 60
    const/4 v12, 0x0

    .line 61
    const/4 v13, 0x0

    .line 62
    const/4 v14, 0x0

    .line 63
    invoke-static/range {v8 .. v16}, Lnh/v;->a(Lnh/v;Ljava/lang/String;ZZZLlc/l;Ljava/util/ArrayList;Lnh/h;I)Lnh/v;

    .line 64
    .line 65
    .line 66
    move-result-object v8

    .line 67
    invoke-virtual {v1, v3, v8}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 68
    .line 69
    .line 70
    move-result v3

    .line 71
    if-eqz v3, :cond_2

    .line 72
    .line 73
    iget-object v3, v4, Lnh/u;->d:Ln70/x;

    .line 74
    .line 75
    iput v6, v0, Lnh/s;->e:I

    .line 76
    .line 77
    invoke-virtual {v3, v0}, Ln70/x;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 78
    .line 79
    .line 80
    move-result-object v0

    .line 81
    if-ne v0, v7, :cond_3

    .line 82
    .line 83
    move-object v2, v7

    .line 84
    goto/16 :goto_4

    .line 85
    .line 86
    :cond_3
    :goto_0
    check-cast v0, Llx0/o;

    .line 87
    .line 88
    iget-object v0, v0, Llx0/o;->d:Ljava/lang/Object;

    .line 89
    .line 90
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 91
    .line 92
    .line 93
    move-result-object v3

    .line 94
    if-eqz v3, :cond_5

    .line 95
    .line 96
    invoke-static {v3}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 97
    .line 98
    .line 99
    move-result-object v11

    .line 100
    sget-object v3, Lnh/w;->a:Lly0/n;

    .line 101
    .line 102
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 103
    .line 104
    .line 105
    :cond_4
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v3

    .line 109
    move-object v6, v3

    .line 110
    check-cast v6, Lnh/v;

    .line 111
    .line 112
    const/4 v13, 0x0

    .line 113
    const/16 v14, 0x3eb

    .line 114
    .line 115
    const/4 v7, 0x0

    .line 116
    const/4 v8, 0x0

    .line 117
    const/4 v9, 0x0

    .line 118
    const/4 v10, 0x0

    .line 119
    const/4 v12, 0x0

    .line 120
    invoke-static/range {v6 .. v14}, Lnh/v;->a(Lnh/v;Ljava/lang/String;ZZZLlc/l;Ljava/util/ArrayList;Lnh/h;I)Lnh/v;

    .line 121
    .line 122
    .line 123
    move-result-object v4

    .line 124
    invoke-virtual {v1, v3, v4}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 125
    .line 126
    .line 127
    move-result v3

    .line 128
    if-eqz v3, :cond_4

    .line 129
    .line 130
    :cond_5
    instance-of v3, v0, Llx0/n;

    .line 131
    .line 132
    if-nez v3, :cond_9

    .line 133
    .line 134
    check-cast v0, Lwb/k;

    .line 135
    .line 136
    iget-object v0, v0, Lwb/k;->e:Ljava/util/List;

    .line 137
    .line 138
    sget-object v3, Lnh/w;->a:Lly0/n;

    .line 139
    .line 140
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    const-string v3, "cards"

    .line 144
    .line 145
    invoke-static {v0, v3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 146
    .line 147
    .line 148
    check-cast v0, Ljava/lang/Iterable;

    .line 149
    .line 150
    new-instance v9, Ljava/util/ArrayList;

    .line 151
    .line 152
    invoke-direct {v9}, Ljava/util/ArrayList;-><init>()V

    .line 153
    .line 154
    .line 155
    invoke-interface {v0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 156
    .line 157
    .line 158
    move-result-object v0

    .line 159
    :cond_6
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 160
    .line 161
    .line 162
    move-result v3

    .line 163
    if-eqz v3, :cond_7

    .line 164
    .line 165
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object v3

    .line 169
    move-object v4, v3

    .line 170
    check-cast v4, Lwb/e;

    .line 171
    .line 172
    iget-object v4, v4, Lwb/e;->h:Ljava/lang/Boolean;

    .line 173
    .line 174
    sget-object v5, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 175
    .line 176
    invoke-static {v4, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 177
    .line 178
    .line 179
    move-result v4

    .line 180
    if-eqz v4, :cond_6

    .line 181
    .line 182
    invoke-virtual {v9, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 183
    .line 184
    .line 185
    goto :goto_1

    .line 186
    :cond_7
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 187
    .line 188
    .line 189
    move-result-object v0

    .line 190
    move-object v3, v0

    .line 191
    check-cast v3, Lnh/v;

    .line 192
    .line 193
    invoke-virtual {v9}, Ljava/util/ArrayList;->isEmpty()Z

    .line 194
    .line 195
    .line 196
    move-result v4

    .line 197
    if-eqz v4, :cond_8

    .line 198
    .line 199
    sget-object v4, Lnh/g;->a:Lnh/g;

    .line 200
    .line 201
    :goto_2
    move-object v10, v4

    .line 202
    goto :goto_3

    .line 203
    :cond_8
    sget-object v4, Lnh/f;->a:Lnh/f;

    .line 204
    .line 205
    goto :goto_2

    .line 206
    :goto_3
    const/4 v8, 0x0

    .line 207
    const/16 v11, 0x39b

    .line 208
    .line 209
    const/4 v4, 0x0

    .line 210
    const/4 v5, 0x0

    .line 211
    const/4 v6, 0x0

    .line 212
    const/4 v7, 0x0

    .line 213
    invoke-static/range {v3 .. v11}, Lnh/v;->a(Lnh/v;Ljava/lang/String;ZZZLlc/l;Ljava/util/ArrayList;Lnh/h;I)Lnh/v;

    .line 214
    .line 215
    .line 216
    move-result-object v3

    .line 217
    invoke-virtual {v1, v0, v3}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 218
    .line 219
    .line 220
    move-result v0

    .line 221
    if-eqz v0, :cond_7

    .line 222
    .line 223
    :cond_9
    :goto_4
    return-object v2

    .line 224
    :pswitch_0
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 225
    .line 226
    iget v7, v0, Lnh/s;->e:I

    .line 227
    .line 228
    if-eqz v7, :cond_b

    .line 229
    .line 230
    if-ne v7, v6, :cond_a

    .line 231
    .line 232
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    move-object/from16 v0, p1

    .line 236
    .line 237
    goto :goto_5

    .line 238
    :cond_a
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 239
    .line 240
    invoke-direct {v0, v3}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 241
    .line 242
    .line 243
    throw v0

    .line 244
    :cond_b
    invoke-static/range {p1 .. p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 245
    .line 246
    .line 247
    iget-object v3, v4, Lnh/u;->f:Lyy0/c2;

    .line 248
    .line 249
    sget-object v7, Lnh/w;->a:Lly0/n;

    .line 250
    .line 251
    invoke-static {v3, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 252
    .line 253
    .line 254
    :cond_c
    invoke-virtual {v3}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 255
    .line 256
    .line 257
    move-result-object v7

    .line 258
    move-object v8, v7

    .line 259
    check-cast v8, Lnh/v;

    .line 260
    .line 261
    const/4 v15, 0x0

    .line 262
    const/16 v16, 0x3fd

    .line 263
    .line 264
    const/4 v9, 0x0

    .line 265
    const/4 v10, 0x1

    .line 266
    const/4 v11, 0x0

    .line 267
    const/4 v12, 0x0

    .line 268
    const/4 v13, 0x0

    .line 269
    const/4 v14, 0x0

    .line 270
    invoke-static/range {v8 .. v16}, Lnh/v;->a(Lnh/v;Ljava/lang/String;ZZZLlc/l;Ljava/util/ArrayList;Lnh/h;I)Lnh/v;

    .line 271
    .line 272
    .line 273
    move-result-object v8

    .line 274
    invoke-virtual {v3, v7, v8}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 275
    .line 276
    .line 277
    move-result v7

    .line 278
    if-eqz v7, :cond_c

    .line 279
    .line 280
    iget-object v3, v4, Lnh/u;->e:Ljd/b;

    .line 281
    .line 282
    iget-object v7, v4, Lnh/u;->f:Lyy0/c2;

    .line 283
    .line 284
    invoke-static {v7, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 285
    .line 286
    .line 287
    new-instance v8, Lwb/h;

    .line 288
    .line 289
    invoke-virtual {v7}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 290
    .line 291
    .line 292
    move-result-object v7

    .line 293
    check-cast v7, Lnh/v;

    .line 294
    .line 295
    iget-object v7, v7, Lnh/v;->a:Ljava/lang/String;

    .line 296
    .line 297
    invoke-direct {v8, v7}, Lwb/h;-><init>(Ljava/lang/String;)V

    .line 298
    .line 299
    .line 300
    iput v6, v0, Lnh/s;->e:I

    .line 301
    .line 302
    invoke-virtual {v3, v8, v0}, Ljd/b;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 303
    .line 304
    .line 305
    move-result-object v0

    .line 306
    if-ne v0, v1, :cond_d

    .line 307
    .line 308
    move-object v2, v1

    .line 309
    goto :goto_6

    .line 310
    :cond_d
    :goto_5
    check-cast v0, Llx0/o;

    .line 311
    .line 312
    iget-object v0, v0, Llx0/o;->d:Ljava/lang/Object;

    .line 313
    .line 314
    instance-of v1, v0, Llx0/n;

    .line 315
    .line 316
    if-nez v1, :cond_f

    .line 317
    .line 318
    move-object v1, v0

    .line 319
    check-cast v1, Lwb/k;

    .line 320
    .line 321
    iget-object v1, v4, Lnh/u;->f:Lyy0/c2;

    .line 322
    .line 323
    sget-object v3, Lnh/w;->a:Lly0/n;

    .line 324
    .line 325
    invoke-static {v1, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 326
    .line 327
    .line 328
    :cond_e
    invoke-virtual {v1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object v3

    .line 332
    move-object v6, v3

    .line 333
    check-cast v6, Lnh/v;

    .line 334
    .line 335
    const/4 v12, 0x0

    .line 336
    const/16 v14, 0x1bc

    .line 337
    .line 338
    const-string v7, ""

    .line 339
    .line 340
    const/4 v8, 0x0

    .line 341
    const/4 v9, 0x0

    .line 342
    const/4 v10, 0x0

    .line 343
    const/4 v11, 0x0

    .line 344
    sget-object v13, Lnh/f;->a:Lnh/f;

    .line 345
    .line 346
    invoke-static/range {v6 .. v14}, Lnh/v;->a(Lnh/v;Ljava/lang/String;ZZZLlc/l;Ljava/util/ArrayList;Lnh/h;I)Lnh/v;

    .line 347
    .line 348
    .line 349
    move-result-object v6

    .line 350
    invoke-virtual {v1, v3, v6}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 351
    .line 352
    .line 353
    move-result v3

    .line 354
    if-eqz v3, :cond_e

    .line 355
    .line 356
    :cond_f
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 357
    .line 358
    .line 359
    move-result-object v0

    .line 360
    if-eqz v0, :cond_11

    .line 361
    .line 362
    iget-object v0, v4, Lnh/u;->f:Lyy0/c2;

    .line 363
    .line 364
    sget-object v1, Lnh/w;->a:Lly0/n;

    .line 365
    .line 366
    invoke-static {v0, v5}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 367
    .line 368
    .line 369
    :cond_10
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 370
    .line 371
    .line 372
    move-result-object v1

    .line 373
    move-object v3, v1

    .line 374
    check-cast v3, Lnh/v;

    .line 375
    .line 376
    const/4 v10, 0x0

    .line 377
    const/16 v11, 0x3f5

    .line 378
    .line 379
    const/4 v4, 0x0

    .line 380
    const/4 v5, 0x0

    .line 381
    const/4 v6, 0x0

    .line 382
    const/4 v7, 0x1

    .line 383
    const/4 v8, 0x0

    .line 384
    const/4 v9, 0x0

    .line 385
    invoke-static/range {v3 .. v11}, Lnh/v;->a(Lnh/v;Ljava/lang/String;ZZZLlc/l;Ljava/util/ArrayList;Lnh/h;I)Lnh/v;

    .line 386
    .line 387
    .line 388
    move-result-object v3

    .line 389
    invoke-virtual {v0, v1, v3}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 390
    .line 391
    .line 392
    move-result v1

    .line 393
    if-eqz v1, :cond_10

    .line 394
    .line 395
    :cond_11
    :goto_6
    return-object v2

    .line 396
    nop

    .line 397
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
