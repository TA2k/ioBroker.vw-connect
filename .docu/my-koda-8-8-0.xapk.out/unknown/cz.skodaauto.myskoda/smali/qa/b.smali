.class public final Lqa/b;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:Lla/b0;

.field public f:I

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Z

.field public final synthetic i:Z

.field public final synthetic j:Lla/u;

.field public final synthetic k:Lay0/k;


# direct methods
.method public synthetic constructor <init>(ZZLla/u;Lkotlin/coroutines/Continuation;Lay0/k;I)V
    .locals 0

    .line 1
    iput p6, p0, Lqa/b;->d:I

    .line 2
    .line 3
    iput-boolean p1, p0, Lqa/b;->h:Z

    .line 4
    .line 5
    iput-boolean p2, p0, Lqa/b;->i:Z

    .line 6
    .line 7
    iput-object p3, p0, Lqa/b;->j:Lla/u;

    .line 8
    .line 9
    iput-object p5, p0, Lqa/b;->k:Lay0/k;

    .line 10
    .line 11
    const/4 p1, 0x2

    .line 12
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 9

    .line 1
    iget v0, p0, Lqa/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lqa/b;

    .line 7
    .line 8
    iget-object v6, p0, Lqa/b;->k:Lay0/k;

    .line 9
    .line 10
    const/4 v7, 0x1

    .line 11
    iget-boolean v2, p0, Lqa/b;->h:Z

    .line 12
    .line 13
    iget-boolean v3, p0, Lqa/b;->i:Z

    .line 14
    .line 15
    iget-object v4, p0, Lqa/b;->j:Lla/u;

    .line 16
    .line 17
    move-object v5, p2

    .line 18
    invoke-direct/range {v1 .. v7}, Lqa/b;-><init>(ZZLla/u;Lkotlin/coroutines/Continuation;Lay0/k;I)V

    .line 19
    .line 20
    .line 21
    iput-object p1, v1, Lqa/b;->g:Ljava/lang/Object;

    .line 22
    .line 23
    return-object v1

    .line 24
    :pswitch_0
    move-object v5, p2

    .line 25
    new-instance v2, Lqa/b;

    .line 26
    .line 27
    iget-object v7, p0, Lqa/b;->k:Lay0/k;

    .line 28
    .line 29
    const/4 v8, 0x0

    .line 30
    iget-boolean v3, p0, Lqa/b;->h:Z

    .line 31
    .line 32
    iget-boolean v4, p0, Lqa/b;->i:Z

    .line 33
    .line 34
    iget-object p0, p0, Lqa/b;->j:Lla/u;

    .line 35
    .line 36
    move-object v6, v5

    .line 37
    move-object v5, p0

    .line 38
    invoke-direct/range {v2 .. v8}, Lqa/b;-><init>(ZZLla/u;Lkotlin/coroutines/Continuation;Lay0/k;I)V

    .line 39
    .line 40
    .line 41
    iput-object p1, v2, Lqa/b;->g:Ljava/lang/Object;

    .line 42
    .line 43
    return-object v2

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lqa/b;->d:I

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
    invoke-virtual {p0, p1, p2}, Lqa/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lqa/b;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lqa/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lqa/b;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lqa/b;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lqa/b;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 11

    .line 1
    iget v0, p0, Lqa/b;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lqa/b;->f:I

    .line 9
    .line 10
    iget-object v2, p0, Lqa/b;->k:Lay0/k;

    .line 11
    .line 12
    iget-object v3, p0, Lqa/b;->j:Lla/u;

    .line 13
    .line 14
    iget-boolean v4, p0, Lqa/b;->i:Z

    .line 15
    .line 16
    const/4 v5, 0x4

    .line 17
    const/4 v6, 0x3

    .line 18
    const/4 v7, 0x2

    .line 19
    const/4 v8, 0x1

    .line 20
    if-eqz v1, :cond_4

    .line 21
    .line 22
    if-eq v1, v8, :cond_3

    .line 23
    .line 24
    if-eq v1, v7, :cond_2

    .line 25
    .line 26
    if-eq v1, v6, :cond_1

    .line 27
    .line 28
    if-ne v1, v5, :cond_0

    .line 29
    .line 30
    iget-object p0, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 31
    .line 32
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 33
    .line 34
    .line 35
    move-object v0, p0

    .line 36
    goto/16 :goto_5

    .line 37
    .line 38
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 39
    .line 40
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 41
    .line 42
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    throw p0

    .line 46
    :cond_1
    iget-object v1, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 47
    .line 48
    check-cast v1, Lla/c0;

    .line 49
    .line 50
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    goto/16 :goto_4

    .line 54
    .line 55
    :cond_2
    iget-object v1, p0, Lqa/b;->e:Lla/b0;

    .line 56
    .line 57
    iget-object v7, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 58
    .line 59
    check-cast v7, Lla/c0;

    .line 60
    .line 61
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_3
    iget-object v1, p0, Lqa/b;->e:Lla/b0;

    .line 66
    .line 67
    iget-object v8, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 68
    .line 69
    check-cast v8, Lla/c0;

    .line 70
    .line 71
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    goto :goto_1

    .line 75
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    iget-object p1, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast p1, Lla/c0;

    .line 81
    .line 82
    iget-boolean v1, p0, Lqa/b;->h:Z

    .line 83
    .line 84
    if-eqz v1, :cond_d

    .line 85
    .line 86
    if-eqz v4, :cond_5

    .line 87
    .line 88
    sget-object v1, Lla/b0;->d:Lla/b0;

    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_5
    sget-object v1, Lla/b0;->e:Lla/b0;

    .line 92
    .line 93
    :goto_0
    if-nez v4, :cond_9

    .line 94
    .line 95
    iput-object p1, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 96
    .line 97
    iput-object v1, p0, Lqa/b;->e:Lla/b0;

    .line 98
    .line 99
    iput v8, p0, Lqa/b;->f:I

    .line 100
    .line 101
    invoke-interface {p1, p0}, Lla/c0;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Boolean;

    .line 102
    .line 103
    .line 104
    move-result-object v8

    .line 105
    if-ne v8, v0, :cond_6

    .line 106
    .line 107
    goto/16 :goto_6

    .line 108
    .line 109
    :cond_6
    move-object v10, v8

    .line 110
    move-object v8, p1

    .line 111
    move-object p1, v10

    .line 112
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 113
    .line 114
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 115
    .line 116
    .line 117
    move-result p1

    .line 118
    if-nez p1, :cond_8

    .line 119
    .line 120
    invoke-virtual {v3}, Lla/u;->h()Lla/h;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    iput-object v8, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 125
    .line 126
    iput-object v1, p0, Lqa/b;->e:Lla/b0;

    .line 127
    .line 128
    iput v7, p0, Lqa/b;->f:I

    .line 129
    .line 130
    invoke-virtual {p1, p0}, Lla/h;->a(Lrx0/i;)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    if-ne p1, v0, :cond_7

    .line 135
    .line 136
    goto :goto_6

    .line 137
    :cond_7
    move-object v7, v8

    .line 138
    :goto_2
    move-object p1, v1

    .line 139
    move-object v1, v7

    .line 140
    goto :goto_3

    .line 141
    :cond_8
    move-object p1, v1

    .line 142
    move-object v1, v8

    .line 143
    goto :goto_3

    .line 144
    :cond_9
    move-object v10, v1

    .line 145
    move-object v1, p1

    .line 146
    move-object p1, v10

    .line 147
    :goto_3
    new-instance v7, Lqa/a;

    .line 148
    .line 149
    const/4 v8, 0x1

    .line 150
    const/4 v9, 0x0

    .line 151
    invoke-direct {v7, v9, v2, v8}, Lqa/a;-><init>(Lkotlin/coroutines/Continuation;Lay0/k;I)V

    .line 152
    .line 153
    .line 154
    iput-object v1, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 155
    .line 156
    iput-object v9, p0, Lqa/b;->e:Lla/b0;

    .line 157
    .line 158
    iput v6, p0, Lqa/b;->f:I

    .line 159
    .line 160
    invoke-interface {v1, p1, v7, p0}, Lla/c0;->b(Lla/b0;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object p1

    .line 164
    if-ne p1, v0, :cond_a

    .line 165
    .line 166
    goto :goto_6

    .line 167
    :cond_a
    :goto_4
    if-nez v4, :cond_c

    .line 168
    .line 169
    iput-object p1, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 170
    .line 171
    iput v5, p0, Lqa/b;->f:I

    .line 172
    .line 173
    invoke-interface {v1, p0}, Lla/c0;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Boolean;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    if-ne p0, v0, :cond_b

    .line 178
    .line 179
    goto :goto_6

    .line 180
    :cond_b
    move-object v0, p1

    .line 181
    move-object p1, p0

    .line 182
    :goto_5
    check-cast p1, Ljava/lang/Boolean;

    .line 183
    .line 184
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 185
    .line 186
    .line 187
    move-result p0

    .line 188
    if-nez p0, :cond_e

    .line 189
    .line 190
    invoke-virtual {v3}, Lla/u;->h()Lla/h;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    iget-object p1, p0, Lla/h;->b:Lla/l0;

    .line 195
    .line 196
    iget-object v1, p0, Lla/h;->e:Lla/g;

    .line 197
    .line 198
    iget-object p0, p0, Lla/h;->f:Lla/g;

    .line 199
    .line 200
    invoke-virtual {p1, v1, p0}, Lla/l0;->e(Lay0/a;Lay0/a;)V

    .line 201
    .line 202
    .line 203
    goto :goto_6

    .line 204
    :cond_c
    move-object v0, p1

    .line 205
    goto :goto_6

    .line 206
    :cond_d
    const-string p0, "null cannot be cast to non-null type androidx.room.coroutines.RawConnectionAccessor"

    .line 207
    .line 208
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    check-cast p1, Lna/b0;

    .line 212
    .line 213
    invoke-interface {p1}, Lna/b0;->d()Lua/a;

    .line 214
    .line 215
    .line 216
    move-result-object p0

    .line 217
    invoke-interface {v2, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 218
    .line 219
    .line 220
    move-result-object v0

    .line 221
    :cond_e
    :goto_6
    return-object v0

    .line 222
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 223
    .line 224
    iget v1, p0, Lqa/b;->f:I

    .line 225
    .line 226
    iget-object v2, p0, Lqa/b;->k:Lay0/k;

    .line 227
    .line 228
    iget-object v3, p0, Lqa/b;->j:Lla/u;

    .line 229
    .line 230
    iget-boolean v4, p0, Lqa/b;->i:Z

    .line 231
    .line 232
    const/4 v5, 0x4

    .line 233
    const/4 v6, 0x3

    .line 234
    const/4 v7, 0x2

    .line 235
    const/4 v8, 0x1

    .line 236
    if-eqz v1, :cond_13

    .line 237
    .line 238
    if-eq v1, v8, :cond_12

    .line 239
    .line 240
    if-eq v1, v7, :cond_11

    .line 241
    .line 242
    if-eq v1, v6, :cond_10

    .line 243
    .line 244
    if-ne v1, v5, :cond_f

    .line 245
    .line 246
    iget-object p0, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 247
    .line 248
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 249
    .line 250
    .line 251
    move-object v0, p0

    .line 252
    goto/16 :goto_c

    .line 253
    .line 254
    :cond_f
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 255
    .line 256
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 257
    .line 258
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 259
    .line 260
    .line 261
    throw p0

    .line 262
    :cond_10
    iget-object v1, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 263
    .line 264
    check-cast v1, Lla/c0;

    .line 265
    .line 266
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 267
    .line 268
    .line 269
    goto/16 :goto_b

    .line 270
    .line 271
    :cond_11
    iget-object v1, p0, Lqa/b;->e:Lla/b0;

    .line 272
    .line 273
    iget-object v7, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 274
    .line 275
    check-cast v7, Lla/c0;

    .line 276
    .line 277
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 278
    .line 279
    .line 280
    goto :goto_9

    .line 281
    :cond_12
    iget-object v1, p0, Lqa/b;->e:Lla/b0;

    .line 282
    .line 283
    iget-object v8, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 284
    .line 285
    check-cast v8, Lla/c0;

    .line 286
    .line 287
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 288
    .line 289
    .line 290
    goto :goto_8

    .line 291
    :cond_13
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 292
    .line 293
    .line 294
    iget-object p1, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 295
    .line 296
    check-cast p1, Lla/c0;

    .line 297
    .line 298
    iget-boolean v1, p0, Lqa/b;->h:Z

    .line 299
    .line 300
    if-eqz v1, :cond_1c

    .line 301
    .line 302
    if-eqz v4, :cond_14

    .line 303
    .line 304
    sget-object v1, Lla/b0;->d:Lla/b0;

    .line 305
    .line 306
    goto :goto_7

    .line 307
    :cond_14
    sget-object v1, Lla/b0;->e:Lla/b0;

    .line 308
    .line 309
    :goto_7
    if-nez v4, :cond_18

    .line 310
    .line 311
    iput-object p1, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 312
    .line 313
    iput-object v1, p0, Lqa/b;->e:Lla/b0;

    .line 314
    .line 315
    iput v8, p0, Lqa/b;->f:I

    .line 316
    .line 317
    invoke-interface {p1, p0}, Lla/c0;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Boolean;

    .line 318
    .line 319
    .line 320
    move-result-object v8

    .line 321
    if-ne v8, v0, :cond_15

    .line 322
    .line 323
    goto/16 :goto_d

    .line 324
    .line 325
    :cond_15
    move-object v10, v8

    .line 326
    move-object v8, p1

    .line 327
    move-object p1, v10

    .line 328
    :goto_8
    check-cast p1, Ljava/lang/Boolean;

    .line 329
    .line 330
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 331
    .line 332
    .line 333
    move-result p1

    .line 334
    if-nez p1, :cond_17

    .line 335
    .line 336
    invoke-virtual {v3}, Lla/u;->h()Lla/h;

    .line 337
    .line 338
    .line 339
    move-result-object p1

    .line 340
    iput-object v8, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 341
    .line 342
    iput-object v1, p0, Lqa/b;->e:Lla/b0;

    .line 343
    .line 344
    iput v7, p0, Lqa/b;->f:I

    .line 345
    .line 346
    invoke-virtual {p1, p0}, Lla/h;->a(Lrx0/i;)Ljava/lang/Object;

    .line 347
    .line 348
    .line 349
    move-result-object p1

    .line 350
    if-ne p1, v0, :cond_16

    .line 351
    .line 352
    goto :goto_d

    .line 353
    :cond_16
    move-object v7, v8

    .line 354
    :goto_9
    move-object p1, v1

    .line 355
    move-object v1, v7

    .line 356
    goto :goto_a

    .line 357
    :cond_17
    move-object p1, v1

    .line 358
    move-object v1, v8

    .line 359
    goto :goto_a

    .line 360
    :cond_18
    move-object v10, v1

    .line 361
    move-object v1, p1

    .line 362
    move-object p1, v10

    .line 363
    :goto_a
    new-instance v7, Lqa/a;

    .line 364
    .line 365
    const/4 v8, 0x0

    .line 366
    const/4 v9, 0x0

    .line 367
    invoke-direct {v7, v9, v2, v8}, Lqa/a;-><init>(Lkotlin/coroutines/Continuation;Lay0/k;I)V

    .line 368
    .line 369
    .line 370
    iput-object v1, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 371
    .line 372
    iput-object v9, p0, Lqa/b;->e:Lla/b0;

    .line 373
    .line 374
    iput v6, p0, Lqa/b;->f:I

    .line 375
    .line 376
    invoke-interface {v1, p1, v7, p0}, Lla/c0;->b(Lla/b0;Lay0/n;Lrx0/i;)Ljava/lang/Object;

    .line 377
    .line 378
    .line 379
    move-result-object p1

    .line 380
    if-ne p1, v0, :cond_19

    .line 381
    .line 382
    goto :goto_d

    .line 383
    :cond_19
    :goto_b
    if-nez v4, :cond_1b

    .line 384
    .line 385
    iput-object p1, p0, Lqa/b;->g:Ljava/lang/Object;

    .line 386
    .line 387
    iput v5, p0, Lqa/b;->f:I

    .line 388
    .line 389
    invoke-interface {v1, p0}, Lla/c0;->c(Lkotlin/coroutines/Continuation;)Ljava/lang/Boolean;

    .line 390
    .line 391
    .line 392
    move-result-object p0

    .line 393
    if-ne p0, v0, :cond_1a

    .line 394
    .line 395
    goto :goto_d

    .line 396
    :cond_1a
    move-object v0, p1

    .line 397
    move-object p1, p0

    .line 398
    :goto_c
    check-cast p1, Ljava/lang/Boolean;

    .line 399
    .line 400
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 401
    .line 402
    .line 403
    move-result p0

    .line 404
    if-nez p0, :cond_1d

    .line 405
    .line 406
    invoke-virtual {v3}, Lla/u;->h()Lla/h;

    .line 407
    .line 408
    .line 409
    move-result-object p0

    .line 410
    iget-object p1, p0, Lla/h;->b:Lla/l0;

    .line 411
    .line 412
    iget-object v1, p0, Lla/h;->e:Lla/g;

    .line 413
    .line 414
    iget-object p0, p0, Lla/h;->f:Lla/g;

    .line 415
    .line 416
    invoke-virtual {p1, v1, p0}, Lla/l0;->e(Lay0/a;Lay0/a;)V

    .line 417
    .line 418
    .line 419
    goto :goto_d

    .line 420
    :cond_1b
    move-object v0, p1

    .line 421
    goto :goto_d

    .line 422
    :cond_1c
    const-string p0, "null cannot be cast to non-null type androidx.room.coroutines.RawConnectionAccessor"

    .line 423
    .line 424
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 425
    .line 426
    .line 427
    check-cast p1, Lna/b0;

    .line 428
    .line 429
    invoke-interface {p1}, Lna/b0;->d()Lua/a;

    .line 430
    .line 431
    .line 432
    move-result-object p0

    .line 433
    invoke-interface {v2, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 434
    .line 435
    .line 436
    move-result-object v0

    .line 437
    :cond_1d
    :goto_d
    return-object v0

    .line 438
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
