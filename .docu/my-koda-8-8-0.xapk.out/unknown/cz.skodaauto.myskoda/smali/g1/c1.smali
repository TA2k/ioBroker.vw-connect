.class public final Lg1/c1;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:Lkotlin/jvm/internal/f0;

.field public f:Lkotlin/jvm/internal/f0;

.field public g:I

.field public synthetic h:Ljava/lang/Object;

.field public final synthetic i:Lg1/d1;


# direct methods
.method public constructor <init>(Lg1/d1;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lg1/c1;->d:I

    .line 1
    iput-object p1, p0, Lg1/c1;->i:Lg1/d1;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p2}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method

.method public constructor <init>(Lkotlin/jvm/internal/f0;Lg1/d1;Lkotlin/coroutines/Continuation;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lg1/c1;->d:I

    .line 2
    iput-object p1, p0, Lg1/c1;->f:Lkotlin/jvm/internal/f0;

    iput-object p2, p0, Lg1/c1;->i:Lg1/d1;

    const/4 p1, 0x2

    invoke-direct {p0, p1, p3}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Lg1/c1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lg1/c1;

    .line 7
    .line 8
    iget-object p0, p0, Lg1/c1;->i:Lg1/d1;

    .line 9
    .line 10
    invoke-direct {v0, p0, p2}, Lg1/c1;-><init>(Lg1/d1;Lkotlin/coroutines/Continuation;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, v0, Lg1/c1;->h:Ljava/lang/Object;

    .line 14
    .line 15
    return-object v0

    .line 16
    :pswitch_0
    new-instance v0, Lg1/c1;

    .line 17
    .line 18
    iget-object v1, p0, Lg1/c1;->f:Lkotlin/jvm/internal/f0;

    .line 19
    .line 20
    iget-object p0, p0, Lg1/c1;->i:Lg1/d1;

    .line 21
    .line 22
    invoke-direct {v0, v1, p0, p2}, Lg1/c1;-><init>(Lkotlin/jvm/internal/f0;Lg1/d1;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lg1/c1;->h:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lg1/c1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lvy0/b0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lg1/c1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lg1/c1;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lg1/c1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lay0/k;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Lg1/c1;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Lg1/c1;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lg1/c1;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    nop

    .line 41
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 6

    .line 1
    iget v0, p0, Lg1/c1;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lg1/c1;->g:I

    .line 9
    .line 10
    const/4 v2, 0x0

    .line 11
    iget-object v3, p0, Lg1/c1;->i:Lg1/d1;

    .line 12
    .line 13
    packed-switch v1, :pswitch_data_1

    .line 14
    .line 15
    .line 16
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 17
    .line 18
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 19
    .line 20
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :pswitch_0
    iget-object v1, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 25
    .line 26
    check-cast v1, Lvy0/b0;

    .line 27
    .line 28
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    goto :goto_1

    .line 32
    :pswitch_1
    iget-object v1, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v1, Lvy0/b0;

    .line 35
    .line 36
    :goto_0
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/util/concurrent/CancellationException; {:try_start_0 .. :try_end_0} :catch_2

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :pswitch_2
    iget-object v1, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v1, Lvy0/b0;

    .line 43
    .line 44
    goto :goto_0

    .line 45
    :cond_0
    :goto_1
    move-object v5, v1

    .line 46
    goto :goto_2

    .line 47
    :pswitch_3
    iget-object v1, p0, Lg1/c1;->e:Lkotlin/jvm/internal/f0;

    .line 48
    .line 49
    iget-object v4, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast v4, Lvy0/b0;

    .line 52
    .line 53
    :try_start_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catch Ljava/util/concurrent/CancellationException; {:try_start_1 .. :try_end_1} :catch_0

    .line 54
    .line 55
    .line 56
    :cond_1
    move-object v5, v4

    .line 57
    goto/16 :goto_6

    .line 58
    .line 59
    :catch_0
    move-object v1, v4

    .line 60
    goto/16 :goto_7

    .line 61
    .line 62
    :pswitch_4
    iget-object v1, p0, Lg1/c1;->e:Lkotlin/jvm/internal/f0;

    .line 63
    .line 64
    iget-object v4, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 65
    .line 66
    check-cast v4, Lvy0/b0;

    .line 67
    .line 68
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    goto :goto_5

    .line 72
    :pswitch_5
    iget-object v1, p0, Lg1/c1;->f:Lkotlin/jvm/internal/f0;

    .line 73
    .line 74
    iget-object v4, p0, Lg1/c1;->e:Lkotlin/jvm/internal/f0;

    .line 75
    .line 76
    iget-object v5, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 77
    .line 78
    check-cast v5, Lvy0/b0;

    .line 79
    .line 80
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    goto :goto_3

    .line 84
    :pswitch_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    iget-object p1, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 88
    .line 89
    check-cast p1, Lvy0/b0;

    .line 90
    .line 91
    move-object v5, p1

    .line 92
    :cond_2
    :goto_2
    invoke-static {v5}, Lvy0/e0;->B(Lvy0/b0;)Z

    .line 93
    .line 94
    .line 95
    move-result p1

    .line 96
    if-eqz p1, :cond_7

    .line 97
    .line 98
    new-instance v1, Lkotlin/jvm/internal/f0;

    .line 99
    .line 100
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 101
    .line 102
    .line 103
    iget-object p1, v3, Lg1/d1;->x:Lxy0/j;

    .line 104
    .line 105
    if-eqz p1, :cond_4

    .line 106
    .line 107
    iput-object v5, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 108
    .line 109
    iput-object v1, p0, Lg1/c1;->e:Lkotlin/jvm/internal/f0;

    .line 110
    .line 111
    iput-object v1, p0, Lg1/c1;->f:Lkotlin/jvm/internal/f0;

    .line 112
    .line 113
    const/4 v4, 0x1

    .line 114
    iput v4, p0, Lg1/c1;->g:I

    .line 115
    .line 116
    invoke-virtual {p1, p0}, Lxy0/j;->r(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 117
    .line 118
    .line 119
    move-result-object p1

    .line 120
    if-ne p1, v0, :cond_3

    .line 121
    .line 122
    goto/16 :goto_8

    .line 123
    .line 124
    :cond_3
    move-object v4, v1

    .line 125
    :goto_3
    check-cast p1, Lg1/k0;

    .line 126
    .line 127
    goto :goto_4

    .line 128
    :cond_4
    move-object v4, v1

    .line 129
    move-object p1, v2

    .line 130
    :goto_4
    iput-object p1, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 131
    .line 132
    iget-object p1, v4, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 133
    .line 134
    instance-of v1, p1, Lg1/i0;

    .line 135
    .line 136
    if-eqz v1, :cond_2

    .line 137
    .line 138
    check-cast p1, Lg1/i0;

    .line 139
    .line 140
    iput-object v5, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 141
    .line 142
    iput-object v4, p0, Lg1/c1;->e:Lkotlin/jvm/internal/f0;

    .line 143
    .line 144
    iput-object v2, p0, Lg1/c1;->f:Lkotlin/jvm/internal/f0;

    .line 145
    .line 146
    const/4 v1, 0x2

    .line 147
    iput v1, p0, Lg1/c1;->g:I

    .line 148
    .line 149
    invoke-static {v3, p1, p0}, Lg1/d1;->b1(Lg1/d1;Lg1/i0;Lrx0/c;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    if-ne p1, v0, :cond_5

    .line 154
    .line 155
    goto :goto_8

    .line 156
    :cond_5
    move-object v1, v4

    .line 157
    move-object v4, v5

    .line 158
    :goto_5
    :try_start_2
    new-instance p1, Lg1/c1;

    .line 159
    .line 160
    invoke-direct {p1, v1, v3, v2}, Lg1/c1;-><init>(Lkotlin/jvm/internal/f0;Lg1/d1;Lkotlin/coroutines/Continuation;)V

    .line 161
    .line 162
    .line 163
    iput-object v4, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 164
    .line 165
    iput-object v1, p0, Lg1/c1;->e:Lkotlin/jvm/internal/f0;

    .line 166
    .line 167
    const/4 v5, 0x3

    .line 168
    iput v5, p0, Lg1/c1;->g:I

    .line 169
    .line 170
    invoke-virtual {v3, p1, p0}, Lg1/d1;->e1(Lg1/c1;Lg1/c1;)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object p1
    :try_end_2
    .catch Ljava/util/concurrent/CancellationException; {:try_start_2 .. :try_end_2} :catch_0

    .line 174
    if-ne p1, v0, :cond_1

    .line 175
    .line 176
    goto :goto_8

    .line 177
    :goto_6
    :try_start_3
    iget-object p1, v1, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 178
    .line 179
    instance-of v1, p1, Lg1/j0;

    .line 180
    .line 181
    if-eqz v1, :cond_6

    .line 182
    .line 183
    check-cast p1, Lg1/j0;

    .line 184
    .line 185
    iput-object v5, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 186
    .line 187
    iput-object v2, p0, Lg1/c1;->e:Lkotlin/jvm/internal/f0;

    .line 188
    .line 189
    const/4 v1, 0x4

    .line 190
    iput v1, p0, Lg1/c1;->g:I

    .line 191
    .line 192
    invoke-static {v3, p1, p0}, Lg1/d1;->c1(Lg1/d1;Lg1/j0;Lrx0/c;)Ljava/lang/Object;

    .line 193
    .line 194
    .line 195
    move-result-object p1

    .line 196
    if-ne p1, v0, :cond_2

    .line 197
    .line 198
    goto :goto_8

    .line 199
    :catch_1
    move-object v1, v5

    .line 200
    goto :goto_7

    .line 201
    :cond_6
    instance-of p1, p1, Lg1/g0;

    .line 202
    .line 203
    if-eqz p1, :cond_2

    .line 204
    .line 205
    iput-object v5, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 206
    .line 207
    iput-object v2, p0, Lg1/c1;->e:Lkotlin/jvm/internal/f0;

    .line 208
    .line 209
    const/4 p1, 0x5

    .line 210
    iput p1, p0, Lg1/c1;->g:I

    .line 211
    .line 212
    invoke-static {v3, p0}, Lg1/d1;->a1(Lg1/d1;Lrx0/c;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object p1
    :try_end_3
    .catch Ljava/util/concurrent/CancellationException; {:try_start_3 .. :try_end_3} :catch_1

    .line 216
    if-ne p1, v0, :cond_2

    .line 217
    .line 218
    goto :goto_8

    .line 219
    :catch_2
    :goto_7
    iput-object v1, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 220
    .line 221
    iput-object v2, p0, Lg1/c1;->e:Lkotlin/jvm/internal/f0;

    .line 222
    .line 223
    const/4 p1, 0x6

    .line 224
    iput p1, p0, Lg1/c1;->g:I

    .line 225
    .line 226
    invoke-static {v3, p0}, Lg1/d1;->a1(Lg1/d1;Lrx0/c;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object p1

    .line 230
    if-ne p1, v0, :cond_0

    .line 231
    .line 232
    goto :goto_8

    .line 233
    :cond_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 234
    .line 235
    :goto_8
    return-object v0

    .line 236
    :pswitch_7
    iget-object v0, p0, Lg1/c1;->f:Lkotlin/jvm/internal/f0;

    .line 237
    .line 238
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 239
    .line 240
    iget v2, p0, Lg1/c1;->g:I

    .line 241
    .line 242
    const/4 v3, 0x1

    .line 243
    if-eqz v2, :cond_9

    .line 244
    .line 245
    if-ne v2, v3, :cond_8

    .line 246
    .line 247
    iget-object v2, p0, Lg1/c1;->e:Lkotlin/jvm/internal/f0;

    .line 248
    .line 249
    iget-object v4, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 250
    .line 251
    check-cast v4, Lay0/k;

    .line 252
    .line 253
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 254
    .line 255
    .line 256
    goto :goto_b

    .line 257
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 258
    .line 259
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 260
    .line 261
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 262
    .line 263
    .line 264
    throw p0

    .line 265
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    iget-object p1, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 269
    .line 270
    check-cast p1, Lay0/k;

    .line 271
    .line 272
    move-object v4, p1

    .line 273
    :goto_9
    iget-object p1, v0, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 274
    .line 275
    instance-of v2, p1, Lg1/j0;

    .line 276
    .line 277
    if-nez v2, :cond_e

    .line 278
    .line 279
    instance-of v2, p1, Lg1/g0;

    .line 280
    .line 281
    if-nez v2, :cond_e

    .line 282
    .line 283
    instance-of v2, p1, Lg1/h0;

    .line 284
    .line 285
    const/4 v5, 0x0

    .line 286
    if-eqz v2, :cond_a

    .line 287
    .line 288
    check-cast p1, Lg1/h0;

    .line 289
    .line 290
    goto :goto_a

    .line 291
    :cond_a
    move-object p1, v5

    .line 292
    :goto_a
    if-eqz p1, :cond_b

    .line 293
    .line 294
    invoke-interface {v4, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 295
    .line 296
    .line 297
    :cond_b
    iget-object p1, p0, Lg1/c1;->i:Lg1/d1;

    .line 298
    .line 299
    iget-object p1, p1, Lg1/d1;->x:Lxy0/j;

    .line 300
    .line 301
    if-eqz p1, :cond_d

    .line 302
    .line 303
    iput-object v4, p0, Lg1/c1;->h:Ljava/lang/Object;

    .line 304
    .line 305
    iput-object v0, p0, Lg1/c1;->e:Lkotlin/jvm/internal/f0;

    .line 306
    .line 307
    iput v3, p0, Lg1/c1;->g:I

    .line 308
    .line 309
    invoke-virtual {p1, p0}, Lxy0/j;->r(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 310
    .line 311
    .line 312
    move-result-object p1

    .line 313
    if-ne p1, v1, :cond_c

    .line 314
    .line 315
    goto :goto_d

    .line 316
    :cond_c
    move-object v2, v0

    .line 317
    :goto_b
    move-object v5, p1

    .line 318
    check-cast v5, Lg1/k0;

    .line 319
    .line 320
    goto :goto_c

    .line 321
    :cond_d
    move-object v2, v0

    .line 322
    :goto_c
    iput-object v5, v2, Lkotlin/jvm/internal/f0;->d:Ljava/lang/Object;

    .line 323
    .line 324
    goto :goto_9

    .line 325
    :cond_e
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 326
    .line 327
    :goto_d
    return-object v1

    .line 328
    nop

    .line 329
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
    .end packed-switch

    .line 330
    .line 331
    .line 332
    .line 333
    .line 334
    .line 335
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
