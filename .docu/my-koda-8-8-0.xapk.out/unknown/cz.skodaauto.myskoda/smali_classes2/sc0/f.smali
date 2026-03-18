.class public final Lsc0/f;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lk21/a;

.field public g:Lk21/a;

.field public h:Ljava/lang/String;

.field public i:Ld01/c;

.field public j:Ljava/util/List;

.field public k:Lxl0/g;

.field public l:Lk21/a;


# direct methods
.method public synthetic constructor <init>(Lk21/a;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lsc0/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lsc0/f;->f:Lk21/a;

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
    iget p1, p0, Lsc0/f;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lsc0/f;

    .line 7
    .line 8
    iget-object p0, p0, Lsc0/f;->f:Lk21/a;

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lsc0/f;-><init>(Lk21/a;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lsc0/f;

    .line 16
    .line 17
    iget-object p0, p0, Lsc0/f;->f:Lk21/a;

    .line 18
    .line 19
    const/4 v0, 0x0

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lsc0/f;-><init>(Lk21/a;Lkotlin/coroutines/Continuation;I)V

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
    iget v0, p0, Lsc0/f;->d:I

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
    invoke-virtual {p0, p1, p2}, Lsc0/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lsc0/f;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lsc0/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lsc0/f;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lsc0/f;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lsc0/f;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    .locals 12

    .line 1
    iget v0, p0, Lsc0/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lsc0/f;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    const/4 v3, 0x0

    .line 12
    if-eqz v1, :cond_1

    .line 13
    .line 14
    if-ne v1, v2, :cond_0

    .line 15
    .line 16
    iget-object v0, p0, Lsc0/f;->l:Lk21/a;

    .line 17
    .line 18
    iget-object v1, p0, Lsc0/f;->k:Lxl0/g;

    .line 19
    .line 20
    iget-object v2, p0, Lsc0/f;->j:Ljava/util/List;

    .line 21
    .line 22
    check-cast v2, Ljava/util/List;

    .line 23
    .line 24
    iget-object v4, p0, Lsc0/f;->i:Ld01/c;

    .line 25
    .line 26
    iget-object v5, p0, Lsc0/f;->h:Ljava/lang/String;

    .line 27
    .line 28
    iget-object p0, p0, Lsc0/f;->g:Lk21/a;

    .line 29
    .line 30
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    move-object v6, v2

    .line 34
    move-object v7, v4

    .line 35
    move-object v8, v5

    .line 36
    move-object v4, v0

    .line 37
    :goto_0
    move-object v5, v1

    .line 38
    goto/16 :goto_1

    .line 39
    .line 40
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 41
    .line 42
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 43
    .line 44
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    sget-object p1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 52
    .line 53
    const-class v1, Luc0/b;

    .line 54
    .line 55
    invoke-virtual {p1, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 56
    .line 57
    .line 58
    move-result-object v1

    .line 59
    iget-object v4, p0, Lsc0/f;->f:Lk21/a;

    .line 60
    .line 61
    invoke-virtual {v4, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v1

    .line 65
    check-cast v1, Lxl0/g;

    .line 66
    .line 67
    const/4 v5, 0x2

    .line 68
    new-array v5, v5, [Ldm0/l;

    .line 69
    .line 70
    const-class v6, Lnc0/r;

    .line 71
    .line 72
    invoke-virtual {p1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 73
    .line 74
    .line 75
    move-result-object v6

    .line 76
    invoke-virtual {v4, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 77
    .line 78
    .line 79
    move-result-object v6

    .line 80
    const/4 v7, 0x0

    .line 81
    aput-object v6, v5, v7

    .line 82
    .line 83
    const-class v6, Luc0/c;

    .line 84
    .line 85
    invoke-virtual {p1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 86
    .line 87
    .line 88
    move-result-object v6

    .line 89
    invoke-virtual {v4, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 90
    .line 91
    .line 92
    move-result-object v6

    .line 93
    aput-object v6, v5, v2

    .line 94
    .line 95
    invoke-static {v5}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 96
    .line 97
    .line 98
    move-result-object v5

    .line 99
    const-class v6, Luc0/a;

    .line 100
    .line 101
    invoke-virtual {p1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 102
    .line 103
    .line 104
    move-result-object v6

    .line 105
    invoke-virtual {v4, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 106
    .line 107
    .line 108
    move-result-object v6

    .line 109
    check-cast v6, Ld01/c;

    .line 110
    .line 111
    const-class v7, Ldx/i;

    .line 112
    .line 113
    const-string v8, "null"

    .line 114
    .line 115
    invoke-static {p1, v7, v8}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 116
    .line 117
    .line 118
    move-result-object v7

    .line 119
    const-class v8, Lti0/a;

    .line 120
    .line 121
    invoke-virtual {p1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 122
    .line 123
    .line 124
    move-result-object p1

    .line 125
    invoke-virtual {v4, p1, v7, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    check-cast p1, Lti0/a;

    .line 130
    .line 131
    iput-object v4, p0, Lsc0/f;->g:Lk21/a;

    .line 132
    .line 133
    const-string v7, "bff-api-auth-no-logging"

    .line 134
    .line 135
    iput-object v7, p0, Lsc0/f;->h:Ljava/lang/String;

    .line 136
    .line 137
    iput-object v6, p0, Lsc0/f;->i:Ld01/c;

    .line 138
    .line 139
    move-object v8, v5

    .line 140
    check-cast v8, Ljava/util/List;

    .line 141
    .line 142
    iput-object v8, p0, Lsc0/f;->j:Ljava/util/List;

    .line 143
    .line 144
    iput-object v1, p0, Lsc0/f;->k:Lxl0/g;

    .line 145
    .line 146
    iput-object v4, p0, Lsc0/f;->l:Lk21/a;

    .line 147
    .line 148
    iput v2, p0, Lsc0/f;->e:I

    .line 149
    .line 150
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    if-ne p1, v0, :cond_2

    .line 155
    .line 156
    goto :goto_2

    .line 157
    :cond_2
    move-object p0, v4

    .line 158
    move-object v8, v7

    .line 159
    move-object v7, v6

    .line 160
    move-object v6, v5

    .line 161
    goto :goto_0

    .line 162
    :goto_1
    move-object v9, p1

    .line 163
    check-cast v9, Ldx/i;

    .line 164
    .line 165
    const-class p1, Ldm0/o;

    .line 166
    .line 167
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 168
    .line 169
    invoke-virtual {v0, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    invoke-virtual {p0, p1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object p0

    .line 177
    move-object v10, p0

    .line 178
    check-cast v10, Ldm0/o;

    .line 179
    .line 180
    const/4 v11, 0x0

    .line 181
    invoke-static/range {v4 .. v11}, Lzl0/b;->a(Lk21/a;Lxl0/g;Ljava/util/List;Ld01/c;Ljava/lang/String;Ldx/i;Ldm0/o;Z)Ld01/h0;

    .line 182
    .line 183
    .line 184
    move-result-object v0

    .line 185
    :goto_2
    return-object v0

    .line 186
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 187
    .line 188
    iget v1, p0, Lsc0/f;->e:I

    .line 189
    .line 190
    const/4 v2, 0x1

    .line 191
    const/4 v3, 0x0

    .line 192
    if-eqz v1, :cond_4

    .line 193
    .line 194
    if-ne v1, v2, :cond_3

    .line 195
    .line 196
    iget-object v0, p0, Lsc0/f;->l:Lk21/a;

    .line 197
    .line 198
    iget-object v1, p0, Lsc0/f;->k:Lxl0/g;

    .line 199
    .line 200
    iget-object v2, p0, Lsc0/f;->j:Ljava/util/List;

    .line 201
    .line 202
    check-cast v2, Ljava/util/List;

    .line 203
    .line 204
    iget-object v4, p0, Lsc0/f;->i:Ld01/c;

    .line 205
    .line 206
    iget-object v5, p0, Lsc0/f;->h:Ljava/lang/String;

    .line 207
    .line 208
    iget-object p0, p0, Lsc0/f;->g:Lk21/a;

    .line 209
    .line 210
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 211
    .line 212
    .line 213
    move-object v6, v2

    .line 214
    move-object v7, v4

    .line 215
    move-object v8, v5

    .line 216
    move-object v4, v0

    .line 217
    :goto_3
    move-object v5, v1

    .line 218
    goto/16 :goto_4

    .line 219
    .line 220
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 221
    .line 222
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 223
    .line 224
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 225
    .line 226
    .line 227
    throw p0

    .line 228
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    sget-object p1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 232
    .line 233
    const-class v1, Luc0/b;

    .line 234
    .line 235
    invoke-virtual {p1, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 236
    .line 237
    .line 238
    move-result-object v1

    .line 239
    iget-object v4, p0, Lsc0/f;->f:Lk21/a;

    .line 240
    .line 241
    invoke-virtual {v4, v1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 242
    .line 243
    .line 244
    move-result-object v1

    .line 245
    check-cast v1, Lxl0/g;

    .line 246
    .line 247
    const/4 v5, 0x2

    .line 248
    new-array v5, v5, [Ldm0/l;

    .line 249
    .line 250
    const-class v6, Lnc0/r;

    .line 251
    .line 252
    invoke-virtual {p1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 253
    .line 254
    .line 255
    move-result-object v6

    .line 256
    invoke-virtual {v4, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 257
    .line 258
    .line 259
    move-result-object v6

    .line 260
    const/4 v7, 0x0

    .line 261
    aput-object v6, v5, v7

    .line 262
    .line 263
    const-class v6, Luc0/c;

    .line 264
    .line 265
    invoke-virtual {p1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 266
    .line 267
    .line 268
    move-result-object v6

    .line 269
    invoke-virtual {v4, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object v6

    .line 273
    aput-object v6, v5, v2

    .line 274
    .line 275
    invoke-static {v5}, Ljp/k1;->j([Ljava/lang/Object;)Ljava/util/List;

    .line 276
    .line 277
    .line 278
    move-result-object v5

    .line 279
    const-class v6, Luc0/a;

    .line 280
    .line 281
    invoke-virtual {p1, v6}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 282
    .line 283
    .line 284
    move-result-object v6

    .line 285
    invoke-virtual {v4, v6, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 286
    .line 287
    .line 288
    move-result-object v6

    .line 289
    check-cast v6, Ld01/c;

    .line 290
    .line 291
    const-class v7, Ldx/i;

    .line 292
    .line 293
    const-string v8, "null"

    .line 294
    .line 295
    invoke-static {p1, v7, v8}, Lia/b;->f(Lkotlin/jvm/internal/h0;Ljava/lang/Class;Ljava/lang/String;)Lh21/b;

    .line 296
    .line 297
    .line 298
    move-result-object v7

    .line 299
    const-class v8, Lti0/a;

    .line 300
    .line 301
    invoke-virtual {p1, v8}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 302
    .line 303
    .line 304
    move-result-object p1

    .line 305
    invoke-virtual {v4, p1, v7, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 306
    .line 307
    .line 308
    move-result-object p1

    .line 309
    check-cast p1, Lti0/a;

    .line 310
    .line 311
    iput-object v4, p0, Lsc0/f;->g:Lk21/a;

    .line 312
    .line 313
    const-string v7, "bff-api-auth"

    .line 314
    .line 315
    iput-object v7, p0, Lsc0/f;->h:Ljava/lang/String;

    .line 316
    .line 317
    iput-object v6, p0, Lsc0/f;->i:Ld01/c;

    .line 318
    .line 319
    move-object v8, v5

    .line 320
    check-cast v8, Ljava/util/List;

    .line 321
    .line 322
    iput-object v8, p0, Lsc0/f;->j:Ljava/util/List;

    .line 323
    .line 324
    iput-object v1, p0, Lsc0/f;->k:Lxl0/g;

    .line 325
    .line 326
    iput-object v4, p0, Lsc0/f;->l:Lk21/a;

    .line 327
    .line 328
    iput v2, p0, Lsc0/f;->e:I

    .line 329
    .line 330
    invoke-interface {p1, p0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 331
    .line 332
    .line 333
    move-result-object p1

    .line 334
    if-ne p1, v0, :cond_5

    .line 335
    .line 336
    goto :goto_5

    .line 337
    :cond_5
    move-object p0, v4

    .line 338
    move-object v8, v7

    .line 339
    move-object v7, v6

    .line 340
    move-object v6, v5

    .line 341
    goto :goto_3

    .line 342
    :goto_4
    move-object v9, p1

    .line 343
    check-cast v9, Ldx/i;

    .line 344
    .line 345
    const-class p1, Ldm0/o;

    .line 346
    .line 347
    sget-object v0, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 348
    .line 349
    invoke-virtual {v0, p1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 350
    .line 351
    .line 352
    move-result-object p1

    .line 353
    invoke-virtual {p0, p1, v3, v3}, Lk21/a;->a(Lhy0/d;Lh21/a;Lay0/a;)Ljava/lang/Object;

    .line 354
    .line 355
    .line 356
    move-result-object p0

    .line 357
    move-object v10, p0

    .line 358
    check-cast v10, Ldm0/o;

    .line 359
    .line 360
    const/16 v11, 0x40

    .line 361
    .line 362
    invoke-static/range {v4 .. v11}, Lzl0/b;->b(Lk21/a;Lxl0/g;Ljava/util/List;Ld01/c;Ljava/lang/String;Ldx/i;Ldm0/o;I)Ld01/h0;

    .line 363
    .line 364
    .line 365
    move-result-object v0

    .line 366
    :goto_5
    return-object v0

    .line 367
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
