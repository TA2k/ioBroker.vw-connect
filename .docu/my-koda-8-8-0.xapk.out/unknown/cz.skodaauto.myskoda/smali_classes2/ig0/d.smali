.class public final Lig0/d;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Lig0/g;

.field public final synthetic h:J


# direct methods
.method public synthetic constructor <init>(Lig0/g;JLkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p5, p0, Lig0/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lig0/d;->g:Lig0/g;

    .line 4
    .line 5
    iput-wide p2, p0, Lig0/d;->h:J

    .line 6
    .line 7
    const/4 p1, 0x2

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 8

    .line 1
    iget v0, p0, Lig0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v1, Lig0/d;

    .line 7
    .line 8
    iget-wide v3, p0, Lig0/d;->h:J

    .line 9
    .line 10
    const/4 v6, 0x2

    .line 11
    iget-object v2, p0, Lig0/d;->g:Lig0/g;

    .line 12
    .line 13
    move-object v5, p2

    .line 14
    invoke-direct/range {v1 .. v6}, Lig0/d;-><init>(Lig0/g;JLkotlin/coroutines/Continuation;I)V

    .line 15
    .line 16
    .line 17
    iput-object p1, v1, Lig0/d;->f:Ljava/lang/Object;

    .line 18
    .line 19
    return-object v1

    .line 20
    :pswitch_0
    move-object v6, p2

    .line 21
    new-instance v2, Lig0/d;

    .line 22
    .line 23
    iget-wide v4, p0, Lig0/d;->h:J

    .line 24
    .line 25
    const/4 v7, 0x1

    .line 26
    iget-object v3, p0, Lig0/d;->g:Lig0/g;

    .line 27
    .line 28
    invoke-direct/range {v2 .. v7}, Lig0/d;-><init>(Lig0/g;JLkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    iput-object p1, v2, Lig0/d;->f:Ljava/lang/Object;

    .line 32
    .line 33
    return-object v2

    .line 34
    :pswitch_1
    move-object v6, p2

    .line 35
    new-instance v2, Lig0/d;

    .line 36
    .line 37
    iget-wide v4, p0, Lig0/d;->h:J

    .line 38
    .line 39
    const/4 v7, 0x0

    .line 40
    iget-object v3, p0, Lig0/d;->g:Lig0/g;

    .line 41
    .line 42
    invoke-direct/range {v2 .. v7}, Lig0/d;-><init>(Lig0/g;JLkotlin/coroutines/Continuation;I)V

    .line 43
    .line 44
    .line 45
    iput-object p1, v2, Lig0/d;->f:Ljava/lang/Object;

    .line 46
    .line 47
    return-object v2

    .line 48
    nop

    .line 49
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lig0/d;->d:I

    .line 2
    .line 3
    check-cast p1, Lyy0/j;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lig0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lig0/d;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lig0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lig0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lig0/d;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lig0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lig0/d;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lig0/d;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lig0/d;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lig0/d;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lig0/d;->g:Lig0/g;

    .line 7
    .line 8
    iget-object v0, v0, Lig0/g;->i:Lyy0/q1;

    .line 9
    .line 10
    iget-object v1, p0, Lig0/d;->f:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast v1, Lyy0/j;

    .line 13
    .line 14
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 15
    .line 16
    iget v3, p0, Lig0/d;->e:I

    .line 17
    .line 18
    const/4 v4, 0x2

    .line 19
    const/4 v5, 0x1

    .line 20
    if-eqz v3, :cond_2

    .line 21
    .line 22
    if-eq v3, v5, :cond_1

    .line 23
    .line 24
    if-ne v3, v4, :cond_0

    .line 25
    .line 26
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    goto :goto_1

    .line 30
    :cond_0
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
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    new-instance p1, Lig0/c;

    .line 46
    .line 47
    const/4 v3, 0x2

    .line 48
    iget-wide v6, p0, Lig0/d;->h:J

    .line 49
    .line 50
    invoke-direct {p1, v0, v6, v7, v3}, Lig0/c;-><init>(Lyy0/q1;JI)V

    .line 51
    .line 52
    .line 53
    iput-object v1, p0, Lig0/d;->f:Ljava/lang/Object;

    .line 54
    .line 55
    iput v5, p0, Lig0/d;->e:I

    .line 56
    .line 57
    invoke-static {p1, p0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p1

    .line 61
    if-ne p1, v2, :cond_3

    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_3
    :goto_0
    check-cast p1, Llg0/i;

    .line 65
    .line 66
    invoke-virtual {v0}, Lyy0/q1;->q()V

    .line 67
    .line 68
    .line 69
    new-instance v0, Lne0/e;

    .line 70
    .line 71
    iget-boolean p1, p1, Llg0/i;->b:Z

    .line 72
    .line 73
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 74
    .line 75
    .line 76
    move-result-object p1

    .line 77
    invoke-direct {v0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    const/4 p1, 0x0

    .line 81
    iput-object p1, p0, Lig0/d;->f:Ljava/lang/Object;

    .line 82
    .line 83
    iput v4, p0, Lig0/d;->e:I

    .line 84
    .line 85
    invoke-interface {v1, v0, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    if-ne p0, v2, :cond_4

    .line 90
    .line 91
    goto :goto_2

    .line 92
    :cond_4
    :goto_1
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 93
    .line 94
    :goto_2
    return-object v2

    .line 95
    :pswitch_0
    iget-object v0, p0, Lig0/d;->g:Lig0/g;

    .line 96
    .line 97
    iget-object v0, v0, Lig0/g;->f:Lyy0/q1;

    .line 98
    .line 99
    iget-object v1, p0, Lig0/d;->f:Ljava/lang/Object;

    .line 100
    .line 101
    check-cast v1, Lyy0/j;

    .line 102
    .line 103
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 104
    .line 105
    iget v3, p0, Lig0/d;->e:I

    .line 106
    .line 107
    const/4 v4, 0x2

    .line 108
    const/4 v5, 0x1

    .line 109
    if-eqz v3, :cond_7

    .line 110
    .line 111
    if-eq v3, v5, :cond_6

    .line 112
    .line 113
    if-ne v3, v4, :cond_5

    .line 114
    .line 115
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    goto :goto_4

    .line 119
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 120
    .line 121
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 122
    .line 123
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 124
    .line 125
    .line 126
    throw p0

    .line 127
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    goto :goto_3

    .line 131
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    new-instance p1, Lig0/c;

    .line 135
    .line 136
    const/4 v3, 0x1

    .line 137
    iget-wide v6, p0, Lig0/d;->h:J

    .line 138
    .line 139
    invoke-direct {p1, v0, v6, v7, v3}, Lig0/c;-><init>(Lyy0/q1;JI)V

    .line 140
    .line 141
    .line 142
    iput-object v1, p0, Lig0/d;->f:Ljava/lang/Object;

    .line 143
    .line 144
    iput v5, p0, Lig0/d;->e:I

    .line 145
    .line 146
    invoke-static {p1, p0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 147
    .line 148
    .line 149
    move-result-object p1

    .line 150
    if-ne p1, v2, :cond_8

    .line 151
    .line 152
    goto :goto_5

    .line 153
    :cond_8
    :goto_3
    check-cast p1, Llg0/h;

    .line 154
    .line 155
    invoke-virtual {v0}, Lyy0/q1;->q()V

    .line 156
    .line 157
    .line 158
    new-instance v0, Lne0/e;

    .line 159
    .line 160
    iget-boolean p1, p1, Llg0/h;->b:Z

    .line 161
    .line 162
    invoke-static {p1}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 163
    .line 164
    .line 165
    move-result-object p1

    .line 166
    invoke-direct {v0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    const/4 p1, 0x0

    .line 170
    iput-object p1, p0, Lig0/d;->f:Ljava/lang/Object;

    .line 171
    .line 172
    iput v4, p0, Lig0/d;->e:I

    .line 173
    .line 174
    invoke-interface {v1, v0, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object p0

    .line 178
    if-ne p0, v2, :cond_9

    .line 179
    .line 180
    goto :goto_5

    .line 181
    :cond_9
    :goto_4
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 182
    .line 183
    :goto_5
    return-object v2

    .line 184
    :pswitch_1
    iget-object v0, p0, Lig0/d;->g:Lig0/g;

    .line 185
    .line 186
    iget-object v0, v0, Lig0/g;->c:Lyy0/q1;

    .line 187
    .line 188
    iget-object v1, p0, Lig0/d;->f:Ljava/lang/Object;

    .line 189
    .line 190
    check-cast v1, Lyy0/j;

    .line 191
    .line 192
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 193
    .line 194
    iget v3, p0, Lig0/d;->e:I

    .line 195
    .line 196
    const/4 v4, 0x3

    .line 197
    const/4 v5, 0x2

    .line 198
    const/4 v6, 0x1

    .line 199
    if-eqz v3, :cond_d

    .line 200
    .line 201
    if-eq v3, v6, :cond_c

    .line 202
    .line 203
    if-eq v3, v5, :cond_b

    .line 204
    .line 205
    if-ne v3, v4, :cond_a

    .line 206
    .line 207
    goto :goto_6

    .line 208
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 209
    .line 210
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 211
    .line 212
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 213
    .line 214
    .line 215
    throw p0

    .line 216
    :cond_b
    :goto_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 217
    .line 218
    .line 219
    goto/16 :goto_8

    .line 220
    .line 221
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    goto :goto_7

    .line 225
    :cond_d
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 226
    .line 227
    .line 228
    new-instance p1, Lig0/c;

    .line 229
    .line 230
    const/4 v3, 0x0

    .line 231
    iget-wide v7, p0, Lig0/d;->h:J

    .line 232
    .line 233
    invoke-direct {p1, v0, v7, v8, v3}, Lig0/c;-><init>(Lyy0/q1;JI)V

    .line 234
    .line 235
    .line 236
    iput-object v1, p0, Lig0/d;->f:Ljava/lang/Object;

    .line 237
    .line 238
    iput v6, p0, Lig0/d;->e:I

    .line 239
    .line 240
    invoke-static {p1, p0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 241
    .line 242
    .line 243
    move-result-object p1

    .line 244
    if-ne p1, v2, :cond_e

    .line 245
    .line 246
    goto :goto_9

    .line 247
    :cond_e
    :goto_7
    check-cast p1, Llg0/g;

    .line 248
    .line 249
    invoke-virtual {v0}, Lyy0/q1;->q()V

    .line 250
    .line 251
    .line 252
    iget-boolean v0, p1, Llg0/g;->d:Z

    .line 253
    .line 254
    iget-wide v6, p1, Llg0/g;->b:J

    .line 255
    .line 256
    const/4 v3, 0x0

    .line 257
    if-eqz v0, :cond_f

    .line 258
    .line 259
    new-instance p1, Lne0/e;

    .line 260
    .line 261
    new-instance v0, Llg0/a;

    .line 262
    .line 263
    invoke-direct {v0, v6, v7}, Llg0/a;-><init>(J)V

    .line 264
    .line 265
    .line 266
    invoke-direct {p1, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 267
    .line 268
    .line 269
    iput-object v3, p0, Lig0/d;->f:Ljava/lang/Object;

    .line 270
    .line 271
    iput v5, p0, Lig0/d;->e:I

    .line 272
    .line 273
    invoke-interface {v1, p1, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object p0

    .line 277
    if-ne p0, v2, :cond_10

    .line 278
    .line 279
    goto :goto_9

    .line 280
    :cond_f
    new-instance v5, Lne0/c;

    .line 281
    .line 282
    move-wide v7, v6

    .line 283
    new-instance v6, Lb0/l;

    .line 284
    .line 285
    iget-object p1, p1, Llg0/g;->c:Llg0/f;

    .line 286
    .line 287
    invoke-static {v7, v8}, Llg0/a;->a(J)Ljava/lang/String;

    .line 288
    .line 289
    .line 290
    move-result-object v0

    .line 291
    new-instance v7, Ljava/lang/StringBuilder;

    .line 292
    .line 293
    const-string v8, "File download request did not finish downloading: fileDownloadId: "

    .line 294
    .line 295
    invoke-direct {v7, v8}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 296
    .line 297
    .line 298
    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 299
    .line 300
    .line 301
    const-string v0, ", request status: "

    .line 302
    .line 303
    invoke-virtual {v7, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 304
    .line 305
    .line 306
    invoke-virtual {v7, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 307
    .line 308
    .line 309
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 310
    .line 311
    .line 312
    move-result-object p1

    .line 313
    invoke-direct {v6, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 314
    .line 315
    .line 316
    const/4 v9, 0x0

    .line 317
    const/16 v10, 0x1e

    .line 318
    .line 319
    const/4 v7, 0x0

    .line 320
    const/4 v8, 0x0

    .line 321
    invoke-direct/range {v5 .. v10}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 322
    .line 323
    .line 324
    iput-object v3, p0, Lig0/d;->f:Ljava/lang/Object;

    .line 325
    .line 326
    iput v4, p0, Lig0/d;->e:I

    .line 327
    .line 328
    invoke-interface {v1, v5, p0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 329
    .line 330
    .line 331
    move-result-object p0

    .line 332
    if-ne p0, v2, :cond_10

    .line 333
    .line 334
    goto :goto_9

    .line 335
    :cond_10
    :goto_8
    sget-object v2, Llx0/b0;->a:Llx0/b0;

    .line 336
    .line 337
    :goto_9
    return-object v2

    .line 338
    nop

    .line 339
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
