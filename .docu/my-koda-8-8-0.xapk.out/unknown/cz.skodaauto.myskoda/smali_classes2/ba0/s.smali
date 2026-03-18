.class public final Lba0/s;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final synthetic f:Lba0/v;


# direct methods
.method public synthetic constructor <init>(Lba0/v;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lba0/s;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lba0/s;->f:Lba0/v;

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
    iget p1, p0, Lba0/s;->d:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p1, Lba0/s;

    .line 7
    .line 8
    iget-object p0, p0, Lba0/s;->f:Lba0/v;

    .line 9
    .line 10
    const/4 v0, 0x3

    .line 11
    invoke-direct {p1, p0, p2, v0}, Lba0/s;-><init>(Lba0/v;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    return-object p1

    .line 15
    :pswitch_0
    new-instance p1, Lba0/s;

    .line 16
    .line 17
    iget-object p0, p0, Lba0/s;->f:Lba0/v;

    .line 18
    .line 19
    const/4 v0, 0x2

    .line 20
    invoke-direct {p1, p0, p2, v0}, Lba0/s;-><init>(Lba0/v;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :pswitch_1
    new-instance p1, Lba0/s;

    .line 25
    .line 26
    iget-object p0, p0, Lba0/s;->f:Lba0/v;

    .line 27
    .line 28
    const/4 v0, 0x1

    .line 29
    invoke-direct {p1, p0, p2, v0}, Lba0/s;-><init>(Lba0/v;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    return-object p1

    .line 33
    :pswitch_2
    new-instance p1, Lba0/s;

    .line 34
    .line 35
    iget-object p0, p0, Lba0/s;->f:Lba0/v;

    .line 36
    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p1, p0, p2, v0}, Lba0/s;-><init>(Lba0/v;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    return-object p1

    .line 42
    nop

    .line 43
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lba0/s;->d:I

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
    invoke-virtual {p0, p1, p2}, Lba0/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lba0/s;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lba0/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lba0/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lba0/s;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lba0/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    return-object p0

    .line 36
    :pswitch_1
    invoke-virtual {p0, p1, p2}, Lba0/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    check-cast p0, Lba0/s;

    .line 41
    .line 42
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 43
    .line 44
    invoke-virtual {p0, p1}, Lba0/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    return-object p0

    .line 49
    :pswitch_2
    invoke-virtual {p0, p1, p2}, Lba0/s;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    check-cast p0, Lba0/s;

    .line 54
    .line 55
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 56
    .line 57
    invoke-virtual {p0, p1}, Lba0/s;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    return-object p0

    .line 62
    nop

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget v0, p0, Lba0/s;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 7
    .line 8
    iget v1, p0, Lba0/s;->e:I

    .line 9
    .line 10
    const/4 v2, 0x1

    .line 11
    if-eqz v1, :cond_1

    .line 12
    .line 13
    if-ne v1, v2, :cond_0

    .line 14
    .line 15
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 16
    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 20
    .line 21
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 22
    .line 23
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iget-object p1, p0, Lba0/s;->f:Lba0/v;

    .line 31
    .line 32
    iget-object p1, p1, Lba0/v;->h:Lz90/c;

    .line 33
    .line 34
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    check-cast p1, Lyy0/i;

    .line 39
    .line 40
    iput v2, p0, Lba0/s;->e:I

    .line 41
    .line 42
    invoke-static {p1, p0}, Lyy0/u;->j(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    if-ne p0, v0, :cond_2

    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_2
    :goto_0
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 50
    .line 51
    :goto_1
    return-object v0

    .line 52
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 53
    .line 54
    iget v1, p0, Lba0/s;->e:I

    .line 55
    .line 56
    const/4 v2, 0x1

    .line 57
    if-eqz v1, :cond_4

    .line 58
    .line 59
    if-ne v1, v2, :cond_3

    .line 60
    .line 61
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 66
    .line 67
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 68
    .line 69
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw p0

    .line 73
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    iget-object p1, p0, Lba0/s;->f:Lba0/v;

    .line 77
    .line 78
    iget-object v1, p1, Lba0/v;->p:Lz90/q;

    .line 79
    .line 80
    invoke-static {v1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 81
    .line 82
    .line 83
    move-result-object v1

    .line 84
    check-cast v1, Lyy0/i;

    .line 85
    .line 86
    new-instance v3, Lba0/r;

    .line 87
    .line 88
    const/4 v4, 0x2

    .line 89
    invoke-direct {v3, p1, v4}, Lba0/r;-><init>(Lba0/v;I)V

    .line 90
    .line 91
    .line 92
    iput v2, p0, Lba0/s;->e:I

    .line 93
    .line 94
    invoke-interface {v1, v3, p0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p0

    .line 98
    if-ne p0, v0, :cond_5

    .line 99
    .line 100
    goto :goto_3

    .line 101
    :cond_5
    :goto_2
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 102
    .line 103
    :goto_3
    return-object v0

    .line 104
    :pswitch_1
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 105
    .line 106
    iget v1, p0, Lba0/s;->e:I

    .line 107
    .line 108
    iget-object v2, p0, Lba0/s;->f:Lba0/v;

    .line 109
    .line 110
    const/4 v3, 0x2

    .line 111
    const/4 v4, 0x1

    .line 112
    if-eqz v1, :cond_8

    .line 113
    .line 114
    if-eq v1, v4, :cond_7

    .line 115
    .line 116
    if-ne v1, v3, :cond_6

    .line 117
    .line 118
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    goto :goto_5

    .line 122
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 123
    .line 124
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 125
    .line 126
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    throw p0

    .line 130
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    goto :goto_4

    .line 134
    :cond_8
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    iget-object p1, v2, Lba0/v;->o:Lz90/s;

    .line 138
    .line 139
    iput v4, p0, Lba0/s;->e:I

    .line 140
    .line 141
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 142
    .line 143
    .line 144
    iget-object v9, p1, Lz90/s;->a:Lz90/p;

    .line 145
    .line 146
    move-object v1, v9

    .line 147
    check-cast v1, Lx90/a;

    .line 148
    .line 149
    iget-object v4, v1, Lx90/a;->h:Lyy0/l1;

    .line 150
    .line 151
    iget-object v1, v1, Lx90/a;->b:Lez0/c;

    .line 152
    .line 153
    new-instance v5, La90/r;

    .line 154
    .line 155
    const/4 v6, 0x0

    .line 156
    const/16 v7, 0x1c

    .line 157
    .line 158
    const-class v8, Lz90/p;

    .line 159
    .line 160
    const-string v10, "isDataValid"

    .line 161
    .line 162
    const-string v11, "isDataValid()Z"

    .line 163
    .line 164
    invoke-direct/range {v5 .. v11}, La90/r;-><init>(IILjava/lang/Class;Ljava/lang/Object;Ljava/lang/String;Ljava/lang/String;)V

    .line 165
    .line 166
    .line 167
    new-instance v6, Lq10/k;

    .line 168
    .line 169
    const/16 v7, 0xd

    .line 170
    .line 171
    const/4 v8, 0x0

    .line 172
    invoke-direct {v6, p1, v8, v7}, Lq10/k;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 173
    .line 174
    .line 175
    invoke-static {v4, v1, v5, v6}, Lbb/j0;->h(Lyy0/i;Lez0/a;Lay0/a;Lay0/k;)Lne0/n;

    .line 176
    .line 177
    .line 178
    move-result-object p1

    .line 179
    if-ne p1, v0, :cond_9

    .line 180
    .line 181
    goto :goto_6

    .line 182
    :cond_9
    :goto_4
    check-cast p1, Lyy0/i;

    .line 183
    .line 184
    invoke-static {p1}, Lbb/j0;->d(Lyy0/i;)Lne0/n;

    .line 185
    .line 186
    .line 187
    move-result-object p1

    .line 188
    new-instance v1, Lba0/r;

    .line 189
    .line 190
    const/4 v4, 0x1

    .line 191
    invoke-direct {v1, v2, v4}, Lba0/r;-><init>(Lba0/v;I)V

    .line 192
    .line 193
    .line 194
    iput v3, p0, Lba0/s;->e:I

    .line 195
    .line 196
    invoke-virtual {p1, v1, p0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 197
    .line 198
    .line 199
    move-result-object p0

    .line 200
    if-ne p0, v0, :cond_a

    .line 201
    .line 202
    goto :goto_6

    .line 203
    :cond_a
    :goto_5
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 204
    .line 205
    :goto_6
    return-object v0

    .line 206
    :pswitch_2
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 207
    .line 208
    iget v1, p0, Lba0/s;->e:I

    .line 209
    .line 210
    const/4 v2, 0x1

    .line 211
    if-eqz v1, :cond_c

    .line 212
    .line 213
    if-ne v1, v2, :cond_b

    .line 214
    .line 215
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 216
    .line 217
    .line 218
    goto :goto_7

    .line 219
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 220
    .line 221
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 222
    .line 223
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 224
    .line 225
    .line 226
    throw p0

    .line 227
    :cond_c
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 228
    .line 229
    .line 230
    iget-object v5, p0, Lba0/s;->f:Lba0/v;

    .line 231
    .line 232
    iget-object p1, v5, Lba0/v;->q:Lkf0/v;

    .line 233
    .line 234
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    move-result-object p1

    .line 238
    check-cast p1, Lyy0/i;

    .line 239
    .line 240
    sget-object v1, Lss0/e;->S1:Lss0/e;

    .line 241
    .line 242
    new-instance v3, La50/d;

    .line 243
    .line 244
    const/4 v9, 0x4

    .line 245
    const/4 v10, 0x3

    .line 246
    const/4 v4, 0x2

    .line 247
    const-class v6, Lba0/v;

    .line 248
    .line 249
    const-string v7, "onUpdateCapabilities"

    .line 250
    .line 251
    const-string v8, "onUpdateCapabilities(Lcz/skodaauto/myskoda/library/vehicle/model/Capabilities;)V"

    .line 252
    .line 253
    invoke-direct/range {v3 .. v10}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 254
    .line 255
    .line 256
    invoke-static {p1, v1, v3}, Lkp/u6;->e(Lyy0/i;Lss0/e;Lay0/n;)Lzy0/j;

    .line 257
    .line 258
    .line 259
    move-result-object p1

    .line 260
    new-instance v3, La50/d;

    .line 261
    .line 262
    const/4 v10, 0x4

    .line 263
    const-class v6, Lba0/v;

    .line 264
    .line 265
    const-string v7, "onUpdateCapabilities"

    .line 266
    .line 267
    const-string v8, "onUpdateCapabilities(Lcz/skodaauto/myskoda/library/vehicle/model/Capabilities;)V"

    .line 268
    .line 269
    invoke-direct/range {v3 .. v10}, La50/d;-><init>(ILjava/lang/Object;Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;II)V

    .line 270
    .line 271
    .line 272
    invoke-static {p1, v1, v3}, Llp/rf;->c(Lzy0/j;Lss0/e;Lay0/n;)Lzy0/j;

    .line 273
    .line 274
    .line 275
    move-result-object p1

    .line 276
    new-instance v1, Lba0/r;

    .line 277
    .line 278
    const/4 v3, 0x0

    .line 279
    invoke-direct {v1, v5, v3}, Lba0/r;-><init>(Lba0/v;I)V

    .line 280
    .line 281
    .line 282
    iput v2, p0, Lba0/s;->e:I

    .line 283
    .line 284
    invoke-virtual {p1, v1, p0}, Lzy0/f;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 285
    .line 286
    .line 287
    move-result-object p0

    .line 288
    if-ne p0, v0, :cond_d

    .line 289
    .line 290
    goto :goto_8

    .line 291
    :cond_d
    :goto_7
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 292
    .line 293
    :goto_8
    return-object v0

    .line 294
    nop

    .line 295
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
