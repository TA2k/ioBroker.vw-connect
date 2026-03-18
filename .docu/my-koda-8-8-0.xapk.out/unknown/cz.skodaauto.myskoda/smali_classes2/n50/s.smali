.class public final Ln50/s;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Ln50/w;


# direct methods
.method public synthetic constructor <init>(Ln50/w;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ln50/s;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ln50/s;->f:Ln50/w;

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
    iget p1, p0, Ln50/s;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Ln50/s;

    .line 7
    .line 8
    iget-object p0, p0, Ln50/s;->f:Ln50/w;

    .line 9
    .line 10
    const/4 v0, 0x4

    .line 11
    invoke-direct {p1, p0, p2, v0}, Ln50/s;-><init>(Ln50/w;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Ln50/s;

    .line 16
    .line 17
    iget-object p0, p0, Ln50/s;->f:Ln50/w;

    .line 18
    .line 19
    const/4 v0, 0x3

    .line 20
    invoke-direct {p1, p0, p2, v0}, Ln50/s;-><init>(Ln50/w;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Ln50/s;

    .line 25
    .line 26
    iget-object p0, p0, Ln50/s;->f:Ln50/w;

    .line 27
    .line 28
    const/4 v0, 0x2

    .line 29
    invoke-direct {p1, p0, p2, v0}, Ln50/s;-><init>(Ln50/w;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Ln50/s;

    .line 34
    .line 35
    iget-object p0, p0, Ln50/s;->f:Ln50/w;

    .line 36
    .line 37
    const/4 v0, 0x1

    .line 38
    invoke-direct {p1, p0, p2, v0}, Ln50/s;-><init>(Ln50/w;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    :pswitch_3
    new-instance p1, Ln50/s;

    .line 43
    .line 44
    iget-object p0, p0, Ln50/s;->f:Ln50/w;

    .line 45
    .line 46
    const/4 v0, 0x0

    .line 47
    invoke-direct {p1, p0, p2, v0}, Ln50/s;-><init>(Ln50/w;Lkotlin/coroutines/Continuation;I)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ln50/s;->d:I

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
    invoke-virtual {p0, p1, p2}, Ln50/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ln50/s;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ln50/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Ln50/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Ln50/s;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Ln50/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Ln50/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Ln50/s;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Ln50/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Ln50/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Ln50/s;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Ln50/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    :pswitch_3
    invoke-virtual {p0, p1, p2}, Ln50/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    check-cast p0, Ln50/s;

    .line 67
    .line 68
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 69
    .line 70
    invoke-virtual {p0, p1}, Ln50/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    return-object p0

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 14

    .line 1
    iget v0, p0, Ln50/s;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Ln50/s;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    iget-object v3, p0, Ln50/s;->f:Ln50/w;

    .line 12
    .line 13
    if-eqz v1, :cond_1

    .line 14
    .line 15
    if-ne v1, v2, :cond_0

    .line 16
    .line 17
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 18
    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 24
    .line 25
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0

    .line 29
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    iget-object p1, v3, Ln50/w;->v:Lhh0/a;

    .line 33
    .line 34
    sget-object v1, Lih0/a;->j:Lih0/a;

    .line 35
    .line 36
    iput v2, p0, Ln50/s;->e:I

    .line 37
    .line 38
    invoke-virtual {p1, v1, p0}, Lhh0/a;->b(Lih0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    if-ne p1, v0, :cond_2

    .line 43
    .line 44
    goto/16 :goto_5

    .line 45
    .line 46
    :cond_2
    :goto_0
    check-cast p1, Ljava/lang/Boolean;

    .line 47
    .line 48
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 49
    .line 50
    .line 51
    move-result p0

    .line 52
    sget-object v4, Lbl0/h0;->d:Lbl0/h0;

    .line 53
    .line 54
    sget-object v5, Lbl0/h0;->e:Lbl0/h0;

    .line 55
    .line 56
    sget-object v6, Lbl0/h0;->g:Lbl0/h0;

    .line 57
    .line 58
    sget-object v7, Lbl0/h0;->i:Lbl0/h0;

    .line 59
    .line 60
    sget-object p1, Lbl0/h0;->j:Lbl0/h0;

    .line 61
    .line 62
    if-eqz p0, :cond_3

    .line 63
    .line 64
    :goto_1
    move-object v8, p1

    .line 65
    goto :goto_2

    .line 66
    :cond_3
    const/4 p1, 0x0

    .line 67
    goto :goto_1

    .line 68
    :goto_2
    sget-object v9, Lbl0/h0;->k:Lbl0/h0;

    .line 69
    .line 70
    filled-new-array/range {v4 .. v9}, [Lbl0/h0;

    .line 71
    .line 72
    .line 73
    move-result-object p0

    .line 74
    invoke-static {p0}, Lmx0/n;->t([Ljava/lang/Object;)Ljava/util/List;

    .line 75
    .line 76
    .line 77
    move-result-object p0

    .line 78
    new-instance v6, Ljava/util/ArrayList;

    .line 79
    .line 80
    const/16 p1, 0xa

    .line 81
    .line 82
    invoke-static {p0, p1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 83
    .line 84
    .line 85
    move-result p1

    .line 86
    invoke-direct {v6, p1}, Ljava/util/ArrayList;-><init>(I)V

    .line 87
    .line 88
    .line 89
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 90
    .line 91
    .line 92
    move-result-object p0

    .line 93
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 94
    .line 95
    .line 96
    move-result p1

    .line 97
    if-eqz p1, :cond_4

    .line 98
    .line 99
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    check-cast p1, Lbl0/h0;

    .line 104
    .line 105
    new-instance v0, Ln50/q;

    .line 106
    .line 107
    iget-object v1, v3, Ln50/w;->u:Lij0/a;

    .line 108
    .line 109
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 110
    .line 111
    .line 112
    move-result v2

    .line 113
    const/4 v4, 0x0

    .line 114
    packed-switch v2, :pswitch_data_1

    .line 115
    .line 116
    .line 117
    new-instance p0, La8/r0;

    .line 118
    .line 119
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 120
    .line 121
    .line 122
    throw p0

    .line 123
    :pswitch_0
    new-array v2, v4, [Ljava/lang/Object;

    .line 124
    .line 125
    check-cast v1, Ljj0/f;

    .line 126
    .line 127
    const v4, 0x7f12062e

    .line 128
    .line 129
    .line 130
    invoke-virtual {v1, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 131
    .line 132
    .line 133
    move-result-object v1

    .line 134
    goto :goto_4

    .line 135
    :pswitch_1
    new-array v2, v4, [Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v1, Ljj0/f;

    .line 138
    .line 139
    const v4, 0x7f12065f

    .line 140
    .line 141
    .line 142
    invoke-virtual {v1, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 143
    .line 144
    .line 145
    move-result-object v1

    .line 146
    goto :goto_4

    .line 147
    :pswitch_2
    new-array v2, v4, [Ljava/lang/Object;

    .line 148
    .line 149
    check-cast v1, Ljj0/f;

    .line 150
    .line 151
    const v4, 0x7f12062d

    .line 152
    .line 153
    .line 154
    invoke-virtual {v1, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 155
    .line 156
    .line 157
    move-result-object v1

    .line 158
    goto :goto_4

    .line 159
    :pswitch_3
    new-array v2, v4, [Ljava/lang/Object;

    .line 160
    .line 161
    check-cast v1, Ljj0/f;

    .line 162
    .line 163
    const v4, 0x7f120660

    .line 164
    .line 165
    .line 166
    invoke-virtual {v1, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v1

    .line 170
    goto :goto_4

    .line 171
    :pswitch_4
    new-array v2, v4, [Ljava/lang/Object;

    .line 172
    .line 173
    check-cast v1, Ljj0/f;

    .line 174
    .line 175
    const v4, 0x7f12062c

    .line 176
    .line 177
    .line 178
    invoke-virtual {v1, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 179
    .line 180
    .line 181
    move-result-object v1

    .line 182
    goto :goto_4

    .line 183
    :pswitch_5
    new-array v2, v4, [Ljava/lang/Object;

    .line 184
    .line 185
    check-cast v1, Ljj0/f;

    .line 186
    .line 187
    const v4, 0x7f12065e

    .line 188
    .line 189
    .line 190
    invoke-virtual {v1, v4, v2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 191
    .line 192
    .line 193
    move-result-object v1

    .line 194
    :goto_4
    invoke-direct {v0, p1, v1}, Ln50/q;-><init>(Lbl0/h0;Ljava/lang/String;)V

    .line 195
    .line 196
    .line 197
    invoke-virtual {v6, v0}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 198
    .line 199
    .line 200
    goto :goto_3

    .line 201
    :cond_4
    invoke-virtual {v3}, Lql0/j;->a()Lql0/h;

    .line 202
    .line 203
    .line 204
    move-result-object p0

    .line 205
    move-object v4, p0

    .line 206
    check-cast v4, Ln50/r;

    .line 207
    .line 208
    const/4 v12, 0x0

    .line 209
    const/16 v13, 0xfd

    .line 210
    .line 211
    const/4 v5, 0x0

    .line 212
    const/4 v7, 0x0

    .line 213
    const/4 v8, 0x0

    .line 214
    const/4 v9, 0x0

    .line 215
    const/4 v10, 0x0

    .line 216
    const/4 v11, 0x0

    .line 217
    invoke-static/range {v4 .. v13}, Ln50/r;->a(Ln50/r;Ljava/util/ArrayList;Ljava/util/ArrayList;Ln50/p;ZZZZZI)Ln50/r;

    .line 218
    .line 219
    .line 220
    move-result-object p0

    .line 221
    invoke-virtual {v3, p0}, Lql0/j;->g(Lql0/h;)V

    .line 222
    .line 223
    .line 224
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 225
    .line 226
    :goto_5
    return-object v0

    .line 227
    :pswitch_6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 228
    .line 229
    iget v1, p0, Ln50/s;->e:I

    .line 230
    .line 231
    const/4 v2, 0x1

    .line 232
    if-eqz v1, :cond_6

    .line 233
    .line 234
    if-ne v1, v2, :cond_5

    .line 235
    .line 236
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 237
    .line 238
    .line 239
    goto :goto_6

    .line 240
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 241
    .line 242
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 243
    .line 244
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 245
    .line 246
    .line 247
    throw p0

    .line 248
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 249
    .line 250
    .line 251
    iget-object p1, p0, Ln50/s;->f:Ln50/w;

    .line 252
    .line 253
    iget-object v1, p1, Ln50/w;->k:Lpp0/k0;

    .line 254
    .line 255
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v1

    .line 259
    check-cast v1, Lyy0/i;

    .line 260
    .line 261
    new-instance v3, Ln50/v;

    .line 262
    .line 263
    const/4 v4, 0x1

    .line 264
    invoke-direct {v3, p1, v4}, Ln50/v;-><init>(Ln50/w;I)V

    .line 265
    .line 266
    .line 267
    iput v2, p0, Ln50/s;->e:I

    .line 268
    .line 269
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 270
    .line 271
    .line 272
    move-result-object p0

    .line 273
    if-ne p0, v0, :cond_7

    .line 274
    .line 275
    goto :goto_7

    .line 276
    :cond_7
    :goto_6
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 277
    .line 278
    :goto_7
    return-object v0

    .line 279
    :pswitch_7
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 280
    .line 281
    iget v1, p0, Ln50/s;->e:I

    .line 282
    .line 283
    const/4 v2, 0x1

    .line 284
    if-eqz v1, :cond_9

    .line 285
    .line 286
    if-ne v1, v2, :cond_8

    .line 287
    .line 288
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 289
    .line 290
    .line 291
    goto :goto_8

    .line 292
    :cond_8
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 293
    .line 294
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 295
    .line 296
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 297
    .line 298
    .line 299
    throw p0

    .line 300
    :cond_9
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 301
    .line 302
    .line 303
    iget-object p1, p0, Ln50/s;->f:Ln50/w;

    .line 304
    .line 305
    iget-object v1, p1, Ln50/w;->j:Llk0/i;

    .line 306
    .line 307
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 308
    .line 309
    .line 310
    move-result-object v1

    .line 311
    check-cast v1, Lyy0/i;

    .line 312
    .line 313
    new-instance v3, Ln50/v;

    .line 314
    .line 315
    const/4 v4, 0x0

    .line 316
    invoke-direct {v3, p1, v4}, Ln50/v;-><init>(Ln50/w;I)V

    .line 317
    .line 318
    .line 319
    iput v2, p0, Ln50/s;->e:I

    .line 320
    .line 321
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 322
    .line 323
    .line 324
    move-result-object p0

    .line 325
    if-ne p0, v0, :cond_a

    .line 326
    .line 327
    goto :goto_9

    .line 328
    :cond_a
    :goto_8
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 329
    .line 330
    :goto_9
    return-object v0

    .line 331
    :pswitch_8
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 332
    .line 333
    iget v1, p0, Ln50/s;->e:I

    .line 334
    .line 335
    const/4 v2, 0x1

    .line 336
    if-eqz v1, :cond_c

    .line 337
    .line 338
    if-ne v1, v2, :cond_b

    .line 339
    .line 340
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 341
    .line 342
    .line 343
    goto :goto_a

    .line 344
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 345
    .line 346
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 347
    .line 348
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 349
    .line 350
    .line 351
    throw p0

    .line 352
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 353
    .line 354
    .line 355
    iget-object p1, p0, Ln50/s;->f:Ln50/w;

    .line 356
    .line 357
    iget-object v1, p1, Ln50/w;->s:Lrq0/f;

    .line 358
    .line 359
    new-instance v3, Lsq0/c;

    .line 360
    .line 361
    iget-object p1, p1, Ln50/w;->u:Lij0/a;

    .line 362
    .line 363
    const/4 v4, 0x0

    .line 364
    new-array v5, v4, [Ljava/lang/Object;

    .line 365
    .line 366
    check-cast p1, Ljj0/f;

    .line 367
    .line 368
    const v6, 0x7f120643

    .line 369
    .line 370
    .line 371
    invoke-virtual {p1, v6, v5}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 372
    .line 373
    .line 374
    move-result-object p1

    .line 375
    const/4 v5, 0x6

    .line 376
    const/4 v6, 0x0

    .line 377
    invoke-direct {v3, v5, p1, v6, v6}, Lsq0/c;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 378
    .line 379
    .line 380
    iput v2, p0, Ln50/s;->e:I

    .line 381
    .line 382
    invoke-virtual {v1, v3, v4, p0}, Lrq0/f;->b(Lsq0/c;ZLkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 383
    .line 384
    .line 385
    move-result-object p0

    .line 386
    if-ne p0, v0, :cond_d

    .line 387
    .line 388
    goto :goto_b

    .line 389
    :cond_d
    :goto_a
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 390
    .line 391
    :goto_b
    return-object v0

    .line 392
    :pswitch_9
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 393
    .line 394
    iget v1, p0, Ln50/s;->e:I

    .line 395
    .line 396
    const/4 v2, 0x1

    .line 397
    if-eqz v1, :cond_f

    .line 398
    .line 399
    if-ne v1, v2, :cond_e

    .line 400
    .line 401
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 402
    .line 403
    .line 404
    goto :goto_c

    .line 405
    :cond_e
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 406
    .line 407
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 408
    .line 409
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 410
    .line 411
    .line 412
    throw p0

    .line 413
    :cond_f
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 414
    .line 415
    .line 416
    iput v2, p0, Ln50/s;->e:I

    .line 417
    .line 418
    iget-object p1, p0, Ln50/s;->f:Ln50/w;

    .line 419
    .line 420
    invoke-static {p1, p0}, Ln50/w;->k(Ln50/w;Lrx0/i;)Ljava/lang/Object;

    .line 421
    .line 422
    .line 423
    move-result-object p0

    .line 424
    if-ne p0, v0, :cond_10

    .line 425
    .line 426
    goto :goto_d

    .line 427
    :cond_10
    :goto_c
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 428
    .line 429
    :goto_d
    return-object v0

    .line 430
    nop

    .line 431
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
    .end packed-switch

    .line 432
    .line 433
    .line 434
    .line 435
    .line 436
    .line 437
    .line 438
    .line 439
    .line 440
    .line 441
    .line 442
    .line 443
    :pswitch_data_1
    .packed-switch 0x0
        :pswitch_5
        :pswitch_4
        :pswitch_4
        :pswitch_3
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
