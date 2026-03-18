.class public final Lem0/h;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lem0/m;


# direct methods
.method public synthetic constructor <init>(Lem0/m;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lem0/h;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lem0/h;->f:Lem0/m;

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
    iget p1, p0, Lem0/h;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lem0/h;

    .line 7
    .line 8
    iget-object p0, p0, Lem0/h;->f:Lem0/m;

    .line 9
    .line 10
    const/4 v0, 0x2

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lem0/h;-><init>(Lem0/m;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lem0/h;

    .line 16
    .line 17
    iget-object p0, p0, Lem0/h;->f:Lem0/m;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lem0/h;-><init>(Lem0/m;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lem0/h;

    .line 25
    .line 26
    iget-object p0, p0, Lem0/h;->f:Lem0/m;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lem0/h;-><init>(Lem0/m;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lem0/h;->d:I

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
    invoke-virtual {p0, p1, p2}, Lem0/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lem0/h;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lem0/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lem0/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lem0/h;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lem0/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lem0/h;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lem0/h;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lem0/h;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 11

    .line 1
    iget v0, p0, Lem0/h;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lem0/h;->e:I

    .line 9
    .line 10
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 11
    .line 12
    iget-object v3, p0, Lem0/h;->f:Lem0/m;

    .line 13
    .line 14
    const/4 v4, 0x3

    .line 15
    const/4 v5, 0x2

    .line 16
    const/4 v6, 0x1

    .line 17
    if-eqz v1, :cond_4

    .line 18
    .line 19
    if-eq v1, v6, :cond_3

    .line 20
    .line 21
    if-eq v1, v5, :cond_2

    .line 22
    .line 23
    if-ne v1, v4, :cond_1

    .line 24
    .line 25
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 26
    .line 27
    .line 28
    :cond_0
    move-object v0, v2

    .line 29
    goto :goto_3

    .line 30
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 31
    .line 32
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 33
    .line 34
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_0

    .line 46
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    iget-object p1, v3, Lem0/m;->a:Lti0/a;

    .line 50
    .line 51
    iput v6, p0, Lem0/h;->e:I

    .line 52
    .line 53
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p1

    .line 57
    if-ne p1, v0, :cond_5

    .line 58
    .line 59
    goto :goto_3

    .line 60
    :cond_5
    :goto_0
    check-cast p1, Lem0/f;

    .line 61
    .line 62
    iput v5, p0, Lem0/h;->e:I

    .line 63
    .line 64
    iget-object v1, p1, Lem0/f;->a:Lla/u;

    .line 65
    .line 66
    new-instance v5, Leh/b;

    .line 67
    .line 68
    const/4 v7, 0x7

    .line 69
    invoke-direct {v5, p1, v7}, Leh/b;-><init>(Ljava/lang/Object;I)V

    .line 70
    .line 71
    .line 72
    const/4 p1, 0x0

    .line 73
    invoke-static {p0, v1, v6, p1, v5}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    if-ne p1, v0, :cond_6

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_6
    :goto_1
    check-cast p1, Ljava/util/List;

    .line 81
    .line 82
    iget-object v1, v3, Lem0/m;->c:Lyy0/c2;

    .line 83
    .line 84
    check-cast p1, Ljava/lang/Iterable;

    .line 85
    .line 86
    new-instance v3, Ljava/util/ArrayList;

    .line 87
    .line 88
    const/16 v5, 0xa

    .line 89
    .line 90
    invoke-static {p1, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 91
    .line 92
    .line 93
    move-result v5

    .line 94
    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 95
    .line 96
    .line 97
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 102
    .line 103
    .line 104
    move-result v5

    .line 105
    if-eqz v5, :cond_7

    .line 106
    .line 107
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 108
    .line 109
    .line 110
    move-result-object v5

    .line 111
    check-cast v5, Lem0/g;

    .line 112
    .line 113
    invoke-static {v5}, Lkp/l6;->b(Lem0/g;)Lhm0/b;

    .line 114
    .line 115
    .line 116
    move-result-object v5

    .line 117
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 118
    .line 119
    .line 120
    goto :goto_2

    .line 121
    :cond_7
    iput v4, p0, Lem0/h;->e:I

    .line 122
    .line 123
    invoke-virtual {v1, v3, p0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    if-ne v2, v0, :cond_0

    .line 127
    .line 128
    :goto_3
    return-object v0

    .line 129
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 130
    .line 131
    iget v1, p0, Lem0/h;->e:I

    .line 132
    .line 133
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 134
    .line 135
    iget-object v3, p0, Lem0/h;->f:Lem0/m;

    .line 136
    .line 137
    const/4 v4, 0x3

    .line 138
    const/4 v5, 0x2

    .line 139
    const/4 v6, 0x1

    .line 140
    if-eqz v1, :cond_c

    .line 141
    .line 142
    if-eq v1, v6, :cond_b

    .line 143
    .line 144
    if-eq v1, v5, :cond_a

    .line 145
    .line 146
    if-ne v1, v4, :cond_9

    .line 147
    .line 148
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    :cond_8
    move-object v0, v2

    .line 152
    goto :goto_7

    .line 153
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 154
    .line 155
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 156
    .line 157
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    throw p0

    .line 161
    :cond_a
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    goto :goto_5

    .line 165
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 166
    .line 167
    .line 168
    goto :goto_4

    .line 169
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 170
    .line 171
    .line 172
    iget-object p1, v3, Lem0/m;->a:Lti0/a;

    .line 173
    .line 174
    iput v6, p0, Lem0/h;->e:I

    .line 175
    .line 176
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object p1

    .line 180
    if-ne p1, v0, :cond_d

    .line 181
    .line 182
    goto :goto_7

    .line 183
    :cond_d
    :goto_4
    check-cast p1, Lem0/f;

    .line 184
    .line 185
    iput v5, p0, Lem0/h;->e:I

    .line 186
    .line 187
    iget-object v1, p1, Lem0/f;->a:Lla/u;

    .line 188
    .line 189
    new-instance v5, Leh/b;

    .line 190
    .line 191
    const/16 v7, 0x8

    .line 192
    .line 193
    invoke-direct {v5, p1, v7}, Leh/b;-><init>(Ljava/lang/Object;I)V

    .line 194
    .line 195
    .line 196
    const/4 p1, 0x0

    .line 197
    invoke-static {p0, v1, v6, p1, v5}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object p1

    .line 201
    if-ne p1, v0, :cond_e

    .line 202
    .line 203
    goto :goto_7

    .line 204
    :cond_e
    :goto_5
    check-cast p1, Ljava/util/List;

    .line 205
    .line 206
    iget-object v1, v3, Lem0/m;->c:Lyy0/c2;

    .line 207
    .line 208
    check-cast p1, Ljava/lang/Iterable;

    .line 209
    .line 210
    new-instance v3, Ljava/util/ArrayList;

    .line 211
    .line 212
    const/16 v5, 0xa

    .line 213
    .line 214
    invoke-static {p1, v5}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 215
    .line 216
    .line 217
    move-result v5

    .line 218
    invoke-direct {v3, v5}, Ljava/util/ArrayList;-><init>(I)V

    .line 219
    .line 220
    .line 221
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 222
    .line 223
    .line 224
    move-result-object p1

    .line 225
    :goto_6
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 226
    .line 227
    .line 228
    move-result v5

    .line 229
    if-eqz v5, :cond_f

    .line 230
    .line 231
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object v5

    .line 235
    check-cast v5, Lem0/g;

    .line 236
    .line 237
    invoke-static {v5}, Lkp/l6;->b(Lem0/g;)Lhm0/b;

    .line 238
    .line 239
    .line 240
    move-result-object v5

    .line 241
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 242
    .line 243
    .line 244
    goto :goto_6

    .line 245
    :cond_f
    iput v4, p0, Lem0/h;->e:I

    .line 246
    .line 247
    invoke-virtual {v1, v3, p0}, Lyy0/c2;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 248
    .line 249
    .line 250
    if-ne v2, v0, :cond_8

    .line 251
    .line 252
    :goto_7
    return-object v0

    .line 253
    :pswitch_1
    iget-object v0, p0, Lem0/h;->f:Lem0/m;

    .line 254
    .line 255
    iget-object v1, v0, Lem0/m;->a:Lti0/a;

    .line 256
    .line 257
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 258
    .line 259
    iget v3, p0, Lem0/h;->e:I

    .line 260
    .line 261
    const/4 v4, 0x5

    .line 262
    const/4 v5, 0x4

    .line 263
    const/4 v6, 0x3

    .line 264
    const/4 v7, 0x2

    .line 265
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 266
    .line 267
    const/4 v9, 0x0

    .line 268
    const/4 v10, 0x1

    .line 269
    if-eqz v3, :cond_16

    .line 270
    .line 271
    if-eq v3, v10, :cond_15

    .line 272
    .line 273
    if-eq v3, v7, :cond_14

    .line 274
    .line 275
    if-eq v3, v6, :cond_13

    .line 276
    .line 277
    if-eq v3, v5, :cond_12

    .line 278
    .line 279
    if-ne v3, v4, :cond_11

    .line 280
    .line 281
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 282
    .line 283
    .line 284
    :cond_10
    move-object v2, v8

    .line 285
    goto/16 :goto_e

    .line 286
    .line 287
    :cond_11
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 288
    .line 289
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 290
    .line 291
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 292
    .line 293
    .line 294
    throw p0

    .line 295
    :cond_12
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 296
    .line 297
    .line 298
    goto :goto_c

    .line 299
    :cond_13
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 300
    .line 301
    .line 302
    goto :goto_a

    .line 303
    :cond_14
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 304
    .line 305
    .line 306
    goto :goto_9

    .line 307
    :cond_15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 308
    .line 309
    .line 310
    goto :goto_8

    .line 311
    :cond_16
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 312
    .line 313
    .line 314
    iput v10, p0, Lem0/h;->e:I

    .line 315
    .line 316
    invoke-interface {v1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 317
    .line 318
    .line 319
    move-result-object p1

    .line 320
    if-ne p1, v2, :cond_17

    .line 321
    .line 322
    goto :goto_e

    .line 323
    :cond_17
    :goto_8
    check-cast p1, Lem0/f;

    .line 324
    .line 325
    iput v7, p0, Lem0/h;->e:I

    .line 326
    .line 327
    iget-object p1, p1, Lem0/f;->a:Lla/u;

    .line 328
    .line 329
    new-instance v3, Leh/b;

    .line 330
    .line 331
    const/16 v7, 0x9

    .line 332
    .line 333
    invoke-direct {v3, v7}, Leh/b;-><init>(I)V

    .line 334
    .line 335
    .line 336
    invoke-static {p0, p1, v10, v9, v3}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 337
    .line 338
    .line 339
    move-result-object p1

    .line 340
    if-ne p1, v2, :cond_18

    .line 341
    .line 342
    goto :goto_e

    .line 343
    :cond_18
    :goto_9
    check-cast p1, Ljava/lang/Number;

    .line 344
    .line 345
    invoke-virtual {p1}, Ljava/lang/Number;->intValue()I

    .line 346
    .line 347
    .line 348
    move-result p1

    .line 349
    const/16 v3, 0x12c

    .line 350
    .line 351
    if-le p1, v3, :cond_10

    .line 352
    .line 353
    iput v6, p0, Lem0/h;->e:I

    .line 354
    .line 355
    invoke-interface {v1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 356
    .line 357
    .line 358
    move-result-object p1

    .line 359
    if-ne p1, v2, :cond_19

    .line 360
    .line 361
    goto :goto_e

    .line 362
    :cond_19
    :goto_a
    check-cast p1, Lem0/f;

    .line 363
    .line 364
    iput v5, p0, Lem0/h;->e:I

    .line 365
    .line 366
    iget-object p1, p1, Lem0/f;->a:Lla/u;

    .line 367
    .line 368
    new-instance v1, Leh/b;

    .line 369
    .line 370
    const/4 v3, 0x6

    .line 371
    invoke-direct {v1, v3}, Leh/b;-><init>(I)V

    .line 372
    .line 373
    .line 374
    invoke-static {p0, p1, v9, v10, v1}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 375
    .line 376
    .line 377
    move-result-object p1

    .line 378
    if-ne p1, v2, :cond_1a

    .line 379
    .line 380
    goto :goto_b

    .line 381
    :cond_1a
    move-object p1, v8

    .line 382
    :goto_b
    if-ne p1, v2, :cond_1b

    .line 383
    .line 384
    goto :goto_e

    .line 385
    :cond_1b
    :goto_c
    iput v4, p0, Lem0/h;->e:I

    .line 386
    .line 387
    sget-object p1, Lge0/b;->a:Lcz0/e;

    .line 388
    .line 389
    new-instance v1, Lem0/h;

    .line 390
    .line 391
    const/4 v3, 0x0

    .line 392
    const/4 v4, 0x1

    .line 393
    invoke-direct {v1, v0, v3, v4}, Lem0/h;-><init>(Lem0/m;Lkotlin/coroutines/Continuation;I)V

    .line 394
    .line 395
    .line 396
    invoke-static {p1, v1, p0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 397
    .line 398
    .line 399
    move-result-object p0

    .line 400
    if-ne p0, v2, :cond_1c

    .line 401
    .line 402
    goto :goto_d

    .line 403
    :cond_1c
    move-object p0, v8

    .line 404
    :goto_d
    if-ne p0, v2, :cond_10

    .line 405
    .line 406
    :goto_e
    return-object v2

    .line 407
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
