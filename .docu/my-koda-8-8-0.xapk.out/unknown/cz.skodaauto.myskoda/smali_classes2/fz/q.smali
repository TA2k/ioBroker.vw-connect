.class public final Lfz/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lfz/j;

.field public final b:Lfz/l;

.field public final c:Lfz/g;

.field public final d:Lfz/e;

.field public final e:Lfz/o;

.field public final f:Lfz/u;


# direct methods
.method public constructor <init>(Lfz/j;Lfz/l;Lfz/g;Lfz/e;Lfz/o;Lfz/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfz/q;->a:Lfz/j;

    .line 5
    .line 6
    iput-object p2, p0, Lfz/q;->b:Lfz/l;

    .line 7
    .line 8
    iput-object p3, p0, Lfz/q;->c:Lfz/g;

    .line 9
    .line 10
    iput-object p4, p0, Lfz/q;->d:Lfz/e;

    .line 11
    .line 12
    iput-object p5, p0, Lfz/q;->e:Lfz/o;

    .line 13
    .line 14
    iput-object p6, p0, Lfz/q;->f:Lfz/u;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lfz/q;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p1, Lfz/p;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lfz/p;

    .line 7
    .line 8
    iget v1, v0, Lfz/p;->k:I

    .line 9
    .line 10
    const/high16 v2, -0x80000000

    .line 11
    .line 12
    and-int v3, v1, v2

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v1, v2

    .line 17
    iput v1, v0, Lfz/p;->k:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lfz/p;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lfz/p;-><init>(Lfz/q;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lfz/p;->i:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lfz/p;->k:I

    .line 30
    .line 31
    iget-object v3, p0, Lfz/q;->f:Lfz/u;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    packed-switch v2, :pswitch_data_0

    .line 35
    .line 36
    .line 37
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 40
    .line 41
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    throw p0

    .line 45
    :pswitch_0
    iget-boolean p0, v0, Lfz/p;->h:Z

    .line 46
    .line 47
    iget-boolean v1, v0, Lfz/p;->g:Z

    .line 48
    .line 49
    iget-boolean v2, v0, Lfz/p;->f:Z

    .line 50
    .line 51
    iget-boolean v3, v0, Lfz/p;->e:Z

    .line 52
    .line 53
    iget-boolean v0, v0, Lfz/p;->d:Z

    .line 54
    .line 55
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto/16 :goto_9

    .line 59
    .line 60
    :pswitch_1
    iget-boolean p0, v0, Lfz/p;->h:Z

    .line 61
    .line 62
    iget-boolean v2, v0, Lfz/p;->g:Z

    .line 63
    .line 64
    iget-boolean v5, v0, Lfz/p;->f:Z

    .line 65
    .line 66
    iget-boolean v6, v0, Lfz/p;->e:Z

    .line 67
    .line 68
    iget-boolean v7, v0, Lfz/p;->d:Z

    .line 69
    .line 70
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    move v10, v7

    .line 74
    move v7, v6

    .line 75
    move v6, v10

    .line 76
    goto/16 :goto_6

    .line 77
    .line 78
    :pswitch_2
    iget-boolean p0, v0, Lfz/p;->g:Z

    .line 79
    .line 80
    iget-boolean v2, v0, Lfz/p;->f:Z

    .line 81
    .line 82
    iget-boolean v5, v0, Lfz/p;->e:Z

    .line 83
    .line 84
    iget-boolean v6, v0, Lfz/p;->d:Z

    .line 85
    .line 86
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    goto/16 :goto_5

    .line 90
    .line 91
    :pswitch_3
    iget-boolean v2, v0, Lfz/p;->f:Z

    .line 92
    .line 93
    iget-boolean v5, v0, Lfz/p;->e:Z

    .line 94
    .line 95
    iget-boolean v6, v0, Lfz/p;->d:Z

    .line 96
    .line 97
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    goto/16 :goto_4

    .line 101
    .line 102
    :pswitch_4
    iget-boolean v2, v0, Lfz/p;->e:Z

    .line 103
    .line 104
    iget-boolean v5, v0, Lfz/p;->d:Z

    .line 105
    .line 106
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    goto :goto_3

    .line 110
    :pswitch_5
    iget-boolean v2, v0, Lfz/p;->d:Z

    .line 111
    .line 112
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 113
    .line 114
    .line 115
    move v5, v2

    .line 116
    goto :goto_2

    .line 117
    :pswitch_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 118
    .line 119
    .line 120
    goto :goto_1

    .line 121
    :pswitch_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 122
    .line 123
    .line 124
    iput v4, v0, Lfz/p;->k:I

    .line 125
    .line 126
    iget-object p1, p0, Lfz/q;->a:Lfz/j;

    .line 127
    .line 128
    invoke-virtual {p1, v0}, Lfz/j;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 129
    .line 130
    .line 131
    move-result-object p1

    .line 132
    if-ne p1, v1, :cond_1

    .line 133
    .line 134
    goto/16 :goto_8

    .line 135
    .line 136
    :cond_1
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 137
    .line 138
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 139
    .line 140
    .line 141
    move-result p1

    .line 142
    iput-boolean p1, v0, Lfz/p;->d:Z

    .line 143
    .line 144
    const/4 v2, 0x2

    .line 145
    iput v2, v0, Lfz/p;->k:I

    .line 146
    .line 147
    iget-object v2, p0, Lfz/q;->b:Lfz/l;

    .line 148
    .line 149
    invoke-virtual {v2, v0}, Lfz/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v2

    .line 153
    if-ne v2, v1, :cond_2

    .line 154
    .line 155
    goto/16 :goto_8

    .line 156
    .line 157
    :cond_2
    move v5, p1

    .line 158
    move-object p1, v2

    .line 159
    :goto_2
    check-cast p1, Ljava/lang/Boolean;

    .line 160
    .line 161
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 162
    .line 163
    .line 164
    move-result v2

    .line 165
    iput-boolean v5, v0, Lfz/p;->d:Z

    .line 166
    .line 167
    iput-boolean v2, v0, Lfz/p;->e:Z

    .line 168
    .line 169
    const/4 p1, 0x3

    .line 170
    iput p1, v0, Lfz/p;->k:I

    .line 171
    .line 172
    iget-object p1, p0, Lfz/q;->c:Lfz/g;

    .line 173
    .line 174
    invoke-virtual {p1, v0}, Lfz/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object p1

    .line 178
    if-ne p1, v1, :cond_3

    .line 179
    .line 180
    goto/16 :goto_8

    .line 181
    .line 182
    :cond_3
    :goto_3
    check-cast p1, Ljava/lang/Boolean;

    .line 183
    .line 184
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 185
    .line 186
    .line 187
    move-result p1

    .line 188
    iput-boolean v5, v0, Lfz/p;->d:Z

    .line 189
    .line 190
    iput-boolean v2, v0, Lfz/p;->e:Z

    .line 191
    .line 192
    iput-boolean p1, v0, Lfz/p;->f:Z

    .line 193
    .line 194
    const/4 v6, 0x4

    .line 195
    iput v6, v0, Lfz/p;->k:I

    .line 196
    .line 197
    iget-object v6, p0, Lfz/q;->d:Lfz/e;

    .line 198
    .line 199
    invoke-virtual {v6, v0}, Lfz/e;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 200
    .line 201
    .line 202
    move-result-object v6

    .line 203
    if-ne v6, v1, :cond_4

    .line 204
    .line 205
    goto/16 :goto_8

    .line 206
    .line 207
    :cond_4
    move v10, v2

    .line 208
    move v2, p1

    .line 209
    move-object p1, v6

    .line 210
    move v6, v5

    .line 211
    move v5, v10

    .line 212
    :goto_4
    check-cast p1, Ljava/lang/Boolean;

    .line 213
    .line 214
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 215
    .line 216
    .line 217
    move-result p1

    .line 218
    iput-boolean v6, v0, Lfz/p;->d:Z

    .line 219
    .line 220
    iput-boolean v5, v0, Lfz/p;->e:Z

    .line 221
    .line 222
    iput-boolean v2, v0, Lfz/p;->f:Z

    .line 223
    .line 224
    iput-boolean p1, v0, Lfz/p;->g:Z

    .line 225
    .line 226
    const/4 v7, 0x5

    .line 227
    iput v7, v0, Lfz/p;->k:I

    .line 228
    .line 229
    iget-object p0, p0, Lfz/q;->e:Lfz/o;

    .line 230
    .line 231
    invoke-virtual {p0, v0}, Lfz/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 232
    .line 233
    .line 234
    move-result-object p0

    .line 235
    if-ne p0, v1, :cond_5

    .line 236
    .line 237
    goto :goto_8

    .line 238
    :cond_5
    move v10, p1

    .line 239
    move-object p1, p0

    .line 240
    move p0, v10

    .line 241
    :goto_5
    check-cast p1, Ljava/lang/Boolean;

    .line 242
    .line 243
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 244
    .line 245
    .line 246
    move-result p1

    .line 247
    if-eqz p1, :cond_a

    .line 248
    .line 249
    iput-boolean v6, v0, Lfz/p;->d:Z

    .line 250
    .line 251
    iput-boolean v5, v0, Lfz/p;->e:Z

    .line 252
    .line 253
    iput-boolean v2, v0, Lfz/p;->f:Z

    .line 254
    .line 255
    iput-boolean p0, v0, Lfz/p;->g:Z

    .line 256
    .line 257
    iput-boolean p1, v0, Lfz/p;->h:Z

    .line 258
    .line 259
    const/4 v7, 0x6

    .line 260
    iput v7, v0, Lfz/p;->k:I

    .line 261
    .line 262
    move-object v7, v3

    .line 263
    check-cast v7, Ldz/g;

    .line 264
    .line 265
    invoke-virtual {v7, v0}, Ldz/g;->a(Lrx0/c;)Ljava/lang/Object;

    .line 266
    .line 267
    .line 268
    move-result-object v7

    .line 269
    if-ne v7, v1, :cond_6

    .line 270
    .line 271
    goto :goto_8

    .line 272
    :cond_6
    move v10, v2

    .line 273
    move v2, p0

    .line 274
    move p0, p1

    .line 275
    move-object p1, v7

    .line 276
    move v7, v5

    .line 277
    move v5, v10

    .line 278
    :goto_6
    if-nez p1, :cond_9

    .line 279
    .line 280
    iput-boolean v6, v0, Lfz/p;->d:Z

    .line 281
    .line 282
    iput-boolean v7, v0, Lfz/p;->e:Z

    .line 283
    .line 284
    iput-boolean v5, v0, Lfz/p;->f:Z

    .line 285
    .line 286
    iput-boolean v2, v0, Lfz/p;->g:Z

    .line 287
    .line 288
    iput-boolean p0, v0, Lfz/p;->h:Z

    .line 289
    .line 290
    const/4 p1, 0x7

    .line 291
    iput p1, v0, Lfz/p;->k:I

    .line 292
    .line 293
    check-cast v3, Ldz/g;

    .line 294
    .line 295
    iget-object p1, v3, Ldz/g;->a:Lve0/u;

    .line 296
    .line 297
    invoke-static {}, Ljava/time/Instant;->now()Ljava/time/Instant;

    .line 298
    .line 299
    .line 300
    move-result-object v3

    .line 301
    invoke-virtual {v3}, Ljava/time/Instant;->toEpochMilli()J

    .line 302
    .line 303
    .line 304
    move-result-wide v8

    .line 305
    const-string v3, "PREF_FIRST_ACTIVE_VEHICLE_DETECTED_TIMESTAMP"

    .line 306
    .line 307
    invoke-virtual {p1, v3, v8, v9, v0}, Lve0/u;->m(Ljava/lang/String;JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object p1

    .line 311
    if-ne p1, v1, :cond_7

    .line 312
    .line 313
    goto :goto_7

    .line 314
    :cond_7
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 315
    .line 316
    :goto_7
    if-ne p1, v1, :cond_8

    .line 317
    .line 318
    :goto_8
    return-object v1

    .line 319
    :cond_8
    move v1, v2

    .line 320
    move v2, v5

    .line 321
    move v0, v6

    .line 322
    move v3, v7

    .line 323
    :goto_9
    move p1, p0

    .line 324
    move v6, v0

    .line 325
    move p0, v1

    .line 326
    move v5, v3

    .line 327
    goto :goto_a

    .line 328
    :cond_9
    move p1, p0

    .line 329
    move p0, v2

    .line 330
    move v2, v5

    .line 331
    move v5, v7

    .line 332
    :cond_a
    :goto_a
    if-nez v6, :cond_b

    .line 333
    .line 334
    if-eqz p1, :cond_b

    .line 335
    .line 336
    if-eqz p0, :cond_b

    .line 337
    .line 338
    if-nez v5, :cond_b

    .line 339
    .line 340
    if-nez v2, :cond_b

    .line 341
    .line 342
    goto :goto_b

    .line 343
    :cond_b
    const/4 v4, 0x0

    .line 344
    :goto_b
    invoke-static {v4}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 345
    .line 346
    .line 347
    move-result-object p0

    .line 348
    return-object p0

    .line 349
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
