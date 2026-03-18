.class public final Lqa/e;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:Lla/b0;

.field public f:I

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Lla/u;

.field public final synthetic i:Lay0/k;


# direct methods
.method public synthetic constructor <init>(ILay0/k;Lkotlin/coroutines/Continuation;Lla/u;)V
    .locals 0

    .line 1
    iput p1, p0, Lqa/e;->d:I

    .line 2
    .line 3
    iput-object p4, p0, Lqa/e;->h:Lla/u;

    .line 4
    .line 5
    iput-object p2, p0, Lqa/e;->i:Lay0/k;

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 3

    .line 1
    iget v0, p0, Lqa/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lqa/e;

    .line 7
    .line 8
    iget-object v1, p0, Lqa/e;->i:Lay0/k;

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object p0, p0, Lqa/e;->h:Lla/u;

    .line 12
    .line 13
    invoke-direct {v0, v2, v1, p2, p0}, Lqa/e;-><init>(ILay0/k;Lkotlin/coroutines/Continuation;Lla/u;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Lqa/e;->g:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Lqa/e;

    .line 20
    .line 21
    iget-object v1, p0, Lqa/e;->i:Lay0/k;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    iget-object p0, p0, Lqa/e;->h:Lla/u;

    .line 25
    .line 26
    invoke-direct {v0, v2, v1, p2, p0}, Lqa/e;-><init>(ILay0/k;Lkotlin/coroutines/Continuation;Lla/u;)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Lqa/e;->g:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lqa/e;->d:I

    .line 2
    .line 3
    check-cast p1, Lla/c0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lqa/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lqa/e;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lqa/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lqa/e;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lqa/e;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lqa/e;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 10

    .line 1
    iget v0, p0, Lqa/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lqa/e;->f:I

    .line 9
    .line 10
    iget-object v2, p0, Lqa/e;->h:Lla/u;

    .line 11
    .line 12
    const/4 v3, 0x4

    .line 13
    const/4 v4, 0x3

    .line 14
    const/4 v5, 0x2

    .line 15
    const/4 v6, 0x1

    .line 16
    if-eqz v1, :cond_5

    .line 17
    .line 18
    if-eq v1, v6, :cond_4

    .line 19
    .line 20
    if-eq v1, v5, :cond_3

    .line 21
    .line 22
    if-eq v1, v4, :cond_2

    .line 23
    .line 24
    if-eq v1, v3, :cond_1

    .line 25
    .line 26
    const/4 p0, 0x5

    .line 27
    if-ne v1, p0, :cond_0

    .line 28
    .line 29
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    goto/16 :goto_6

    .line 33
    .line 34
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 35
    .line 36
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 37
    .line 38
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_1
    iget-object p0, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 43
    .line 44
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto/16 :goto_5

    .line 48
    .line 49
    :cond_2
    iget-object v1, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v1, Lla/c0;

    .line 52
    .line 53
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto/16 :goto_3

    .line 57
    .line 58
    :cond_3
    iget-object v1, p0, Lqa/e;->e:Lla/b0;

    .line 59
    .line 60
    iget-object v5, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 61
    .line 62
    check-cast v5, Lla/c0;

    .line 63
    .line 64
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_4
    iget-object v1, p0, Lqa/e;->e:Lla/b0;

    .line 69
    .line 70
    iget-object v6, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 71
    .line 72
    check-cast v6, Lla/c0;

    .line 73
    .line 74
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    goto :goto_0

    .line 78
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    iget-object p1, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 82
    .line 83
    check-cast p1, Lla/c0;

    .line 84
    .line 85
    sget-object v1, Lla/b0;->e:Lla/b0;

    .line 86
    .line 87
    iput-object p1, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 88
    .line 89
    iput-object v1, p0, Lqa/e;->e:Lla/b0;

    .line 90
    .line 91
    iput v6, p0, Lqa/e;->f:I

    .line 92
    .line 93
    invoke-interface {p1, p0}, Lla/c0;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Boolean;

    .line 94
    .line 95
    .line 96
    move-result-object v6

    .line 97
    if-ne v6, v0, :cond_6

    .line 98
    .line 99
    goto :goto_4

    .line 100
    :cond_6
    move-object v9, v6

    .line 101
    move-object v6, p1

    .line 102
    move-object p1, v9

    .line 103
    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    .line 104
    .line 105
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 106
    .line 107
    .line 108
    move-result p1

    .line 109
    if-nez p1, :cond_8

    .line 110
    .line 111
    invoke-virtual {v2}, Lla/u;->h()Lla/h;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    iput-object v6, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 116
    .line 117
    iput-object v1, p0, Lqa/e;->e:Lla/b0;

    .line 118
    .line 119
    iput v5, p0, Lqa/e;->f:I

    .line 120
    .line 121
    invoke-virtual {p1, p0}, Lla/h;->a(Lrx0/i;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    if-ne p1, v0, :cond_7

    .line 126
    .line 127
    goto :goto_4

    .line 128
    :cond_7
    move-object v5, v6

    .line 129
    :goto_1
    move-object p1, v1

    .line 130
    move-object v1, v5

    .line 131
    goto :goto_2

    .line 132
    :cond_8
    move-object p1, v1

    .line 133
    move-object v1, v6

    .line 134
    :goto_2
    new-instance v5, Lew/f;

    .line 135
    .line 136
    const/4 v6, 0x5

    .line 137
    const/4 v7, 0x0

    .line 138
    iget-object v8, p0, Lqa/e;->i:Lay0/k;

    .line 139
    .line 140
    invoke-direct {v5, v7, v8, v6}, Lew/f;-><init>(Lkotlin/coroutines/Continuation;Lay0/k;I)V

    .line 141
    .line 142
    .line 143
    iput-object v1, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 144
    .line 145
    iput-object v7, p0, Lqa/e;->e:Lla/b0;

    .line 146
    .line 147
    iput v4, p0, Lqa/e;->f:I

    .line 148
    .line 149
    invoke-interface {v1, p1, v5, p0}, Lla/c0;->b(Lla/b0;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    if-ne p1, v0, :cond_9

    .line 154
    .line 155
    goto :goto_4

    .line 156
    :cond_9
    :goto_3
    iput-object p1, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 157
    .line 158
    iput v3, p0, Lqa/e;->f:I

    .line 159
    .line 160
    invoke-interface {v1, p0}, Lla/c0;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Boolean;

    .line 161
    .line 162
    .line 163
    move-result-object p0

    .line 164
    if-ne p0, v0, :cond_a

    .line 165
    .line 166
    :goto_4
    move-object p1, v0

    .line 167
    goto :goto_6

    .line 168
    :cond_a
    move-object v9, p1

    .line 169
    move-object p1, p0

    .line 170
    move-object p0, v9

    .line 171
    :goto_5
    check-cast p1, Ljava/lang/Boolean;

    .line 172
    .line 173
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 174
    .line 175
    .line 176
    move-result p1

    .line 177
    if-nez p1, :cond_b

    .line 178
    .line 179
    invoke-virtual {v2}, Lla/u;->h()Lla/h;

    .line 180
    .line 181
    .line 182
    move-result-object p1

    .line 183
    iget-object v0, p1, Lla/h;->b:Lla/l0;

    .line 184
    .line 185
    iget-object v1, p1, Lla/h;->e:Lla/g;

    .line 186
    .line 187
    iget-object p1, p1, Lla/h;->f:Lla/g;

    .line 188
    .line 189
    invoke-virtual {v0, v1, p1}, Lla/l0;->e(Lay0/a;Lay0/a;)V

    .line 190
    .line 191
    .line 192
    :cond_b
    move-object p1, p0

    .line 193
    :goto_6
    return-object p1

    .line 194
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 195
    .line 196
    iget v1, p0, Lqa/e;->f:I

    .line 197
    .line 198
    iget-object v2, p0, Lqa/e;->h:Lla/u;

    .line 199
    .line 200
    const/4 v3, 0x4

    .line 201
    const/4 v4, 0x3

    .line 202
    const/4 v5, 0x2

    .line 203
    const/4 v6, 0x1

    .line 204
    if-eqz v1, :cond_11

    .line 205
    .line 206
    if-eq v1, v6, :cond_10

    .line 207
    .line 208
    if-eq v1, v5, :cond_f

    .line 209
    .line 210
    if-eq v1, v4, :cond_e

    .line 211
    .line 212
    if-eq v1, v3, :cond_d

    .line 213
    .line 214
    const/4 p0, 0x5

    .line 215
    if-ne v1, p0, :cond_c

    .line 216
    .line 217
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 218
    .line 219
    .line 220
    goto/16 :goto_d

    .line 221
    .line 222
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 223
    .line 224
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 225
    .line 226
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    throw p0

    .line 230
    :cond_d
    iget-object p0, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 231
    .line 232
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 233
    .line 234
    .line 235
    goto/16 :goto_c

    .line 236
    .line 237
    :cond_e
    iget-object v1, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 238
    .line 239
    check-cast v1, Lla/c0;

    .line 240
    .line 241
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 242
    .line 243
    .line 244
    goto/16 :goto_a

    .line 245
    .line 246
    :cond_f
    iget-object v1, p0, Lqa/e;->e:Lla/b0;

    .line 247
    .line 248
    iget-object v5, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 249
    .line 250
    check-cast v5, Lla/c0;

    .line 251
    .line 252
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 253
    .line 254
    .line 255
    goto :goto_8

    .line 256
    :cond_10
    iget-object v1, p0, Lqa/e;->e:Lla/b0;

    .line 257
    .line 258
    iget-object v6, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 259
    .line 260
    check-cast v6, Lla/c0;

    .line 261
    .line 262
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 263
    .line 264
    .line 265
    goto :goto_7

    .line 266
    :cond_11
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 267
    .line 268
    .line 269
    iget-object p1, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 270
    .line 271
    check-cast p1, Lla/c0;

    .line 272
    .line 273
    sget-object v1, Lla/b0;->e:Lla/b0;

    .line 274
    .line 275
    iput-object p1, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 276
    .line 277
    iput-object v1, p0, Lqa/e;->e:Lla/b0;

    .line 278
    .line 279
    iput v6, p0, Lqa/e;->f:I

    .line 280
    .line 281
    invoke-interface {p1, p0}, Lla/c0;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Boolean;

    .line 282
    .line 283
    .line 284
    move-result-object v6

    .line 285
    if-ne v6, v0, :cond_12

    .line 286
    .line 287
    goto :goto_b

    .line 288
    :cond_12
    move-object v9, v6

    .line 289
    move-object v6, p1

    .line 290
    move-object p1, v9

    .line 291
    :goto_7
    check-cast p1, Ljava/lang/Boolean;

    .line 292
    .line 293
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 294
    .line 295
    .line 296
    move-result p1

    .line 297
    if-nez p1, :cond_14

    .line 298
    .line 299
    invoke-virtual {v2}, Lla/u;->h()Lla/h;

    .line 300
    .line 301
    .line 302
    move-result-object p1

    .line 303
    iput-object v6, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 304
    .line 305
    iput-object v1, p0, Lqa/e;->e:Lla/b0;

    .line 306
    .line 307
    iput v5, p0, Lqa/e;->f:I

    .line 308
    .line 309
    invoke-virtual {p1, p0}, Lla/h;->a(Lrx0/i;)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object p1

    .line 313
    if-ne p1, v0, :cond_13

    .line 314
    .line 315
    goto :goto_b

    .line 316
    :cond_13
    move-object v5, v6

    .line 317
    :goto_8
    move-object p1, v1

    .line 318
    move-object v1, v5

    .line 319
    goto :goto_9

    .line 320
    :cond_14
    move-object p1, v1

    .line 321
    move-object v1, v6

    .line 322
    :goto_9
    new-instance v5, Lew/f;

    .line 323
    .line 324
    const/4 v6, 0x4

    .line 325
    const/4 v7, 0x0

    .line 326
    iget-object v8, p0, Lqa/e;->i:Lay0/k;

    .line 327
    .line 328
    invoke-direct {v5, v7, v8, v6}, Lew/f;-><init>(Lkotlin/coroutines/Continuation;Lay0/k;I)V

    .line 329
    .line 330
    .line 331
    iput-object v1, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 332
    .line 333
    iput-object v7, p0, Lqa/e;->e:Lla/b0;

    .line 334
    .line 335
    iput v4, p0, Lqa/e;->f:I

    .line 336
    .line 337
    invoke-interface {v1, p1, v5, p0}, Lla/c0;->b(Lla/b0;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 338
    .line 339
    .line 340
    move-result-object p1

    .line 341
    if-ne p1, v0, :cond_15

    .line 342
    .line 343
    goto :goto_b

    .line 344
    :cond_15
    :goto_a
    iput-object p1, p0, Lqa/e;->g:Ljava/lang/Object;

    .line 345
    .line 346
    iput v3, p0, Lqa/e;->f:I

    .line 347
    .line 348
    invoke-interface {v1, p0}, Lla/c0;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Boolean;

    .line 349
    .line 350
    .line 351
    move-result-object p0

    .line 352
    if-ne p0, v0, :cond_16

    .line 353
    .line 354
    :goto_b
    move-object p1, v0

    .line 355
    goto :goto_d

    .line 356
    :cond_16
    move-object v9, p1

    .line 357
    move-object p1, p0

    .line 358
    move-object p0, v9

    .line 359
    :goto_c
    check-cast p1, Ljava/lang/Boolean;

    .line 360
    .line 361
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 362
    .line 363
    .line 364
    move-result p1

    .line 365
    if-nez p1, :cond_17

    .line 366
    .line 367
    invoke-virtual {v2}, Lla/u;->h()Lla/h;

    .line 368
    .line 369
    .line 370
    move-result-object p1

    .line 371
    iget-object v0, p1, Lla/h;->b:Lla/l0;

    .line 372
    .line 373
    iget-object v1, p1, Lla/h;->e:Lla/g;

    .line 374
    .line 375
    iget-object p1, p1, Lla/h;->f:Lla/g;

    .line 376
    .line 377
    invoke-virtual {v0, v1, p1}, Lla/l0;->e(Lay0/a;Lay0/a;)V

    .line 378
    .line 379
    .line 380
    :cond_17
    move-object p1, p0

    .line 381
    :goto_d
    return-object p1

    .line 382
    nop

    .line 383
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
