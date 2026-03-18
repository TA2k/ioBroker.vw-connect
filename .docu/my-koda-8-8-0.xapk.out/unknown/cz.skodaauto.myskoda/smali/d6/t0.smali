.class public final Ld6/t0;
.super Lrx0/h;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic e:I

.field public f:I

.field public synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Ld6/t0;->e:I

    .line 2
    .line 3
    iput-object p1, p0, Ld6/t0;->h:Ljava/lang/Object;

    .line 4
    .line 5
    const/4 p1, 0x2

    .line 6
    invoke-direct {p0, p1, p2}, Lrx0/h;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;
    .locals 2

    .line 1
    iget v0, p0, Ld6/t0;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Ld6/t0;

    .line 7
    .line 8
    iget-object p0, p0, Ld6/t0;->h:Ljava/lang/Object;

    .line 9
    .line 10
    check-cast p0, Lp3/l;

    .line 11
    .line 12
    const/4 v1, 0x3

    .line 13
    invoke-direct {v0, p0, p2, v1}, Ld6/t0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 14
    .line 15
    .line 16
    iput-object p1, v0, Ld6/t0;->g:Ljava/lang/Object;

    .line 17
    .line 18
    return-object v0

    .line 19
    :pswitch_0
    new-instance v0, Ld6/t0;

    .line 20
    .line 21
    iget-object p0, p0, Ld6/t0;->h:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lb71/o;

    .line 24
    .line 25
    const/4 v1, 0x2

    .line 26
    invoke-direct {v0, p0, p2, v1}, Ld6/t0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 27
    .line 28
    .line 29
    iput-object p1, v0, Ld6/t0;->g:Ljava/lang/Object;

    .line 30
    .line 31
    return-object v0

    .line 32
    :pswitch_1
    new-instance v0, Ld6/t0;

    .line 33
    .line 34
    iget-object p0, p0, Ld6/t0;->h:Ljava/lang/Object;

    .line 35
    .line 36
    check-cast p0, Le1/j;

    .line 37
    .line 38
    const/4 v1, 0x1

    .line 39
    invoke-direct {v0, p0, p2, v1}, Ld6/t0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    iput-object p1, v0, Ld6/t0;->g:Ljava/lang/Object;

    .line 43
    .line 44
    return-object v0

    .line 45
    :pswitch_2
    new-instance v0, Ld6/t0;

    .line 46
    .line 47
    iget-object p0, p0, Ld6/t0;->h:Ljava/lang/Object;

    .line 48
    .line 49
    check-cast p0, Landroid/view/View;

    .line 50
    .line 51
    const/4 v1, 0x0

    .line 52
    invoke-direct {v0, p0, p2, v1}, Ld6/t0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 53
    .line 54
    .line 55
    iput-object p1, v0, Ld6/t0;->g:Ljava/lang/Object;

    .line 56
    .line 57
    return-object v0

    .line 58
    nop

    .line 59
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
    iget v0, p0, Ld6/t0;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lp3/i0;

    .line 7
    .line 8
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Ld6/t0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Ld6/t0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Ld6/t0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    check-cast p1, Lp3/i0;

    .line 24
    .line 25
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 26
    .line 27
    invoke-virtual {p0, p1, p2}, Ld6/t0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 28
    .line 29
    .line 30
    move-result-object p0

    .line 31
    check-cast p0, Ld6/t0;

    .line 32
    .line 33
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 34
    .line 35
    invoke-virtual {p0, p1}, Ld6/t0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 36
    .line 37
    .line 38
    move-result-object p0

    .line 39
    return-object p0

    .line 40
    :pswitch_1
    check-cast p1, Lp3/i0;

    .line 41
    .line 42
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 43
    .line 44
    invoke-virtual {p0, p1, p2}, Ld6/t0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    check-cast p0, Ld6/t0;

    .line 49
    .line 50
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 51
    .line 52
    invoke-virtual {p0, p1}, Ld6/t0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0

    .line 57
    :pswitch_2
    check-cast p1, Lky0/k;

    .line 58
    .line 59
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 60
    .line 61
    invoke-virtual {p0, p1, p2}, Ld6/t0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    check-cast p0, Ld6/t0;

    .line 66
    .line 67
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Ld6/t0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p0

    .line 73
    return-object p0

    .line 74
    nop

    .line 75
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 13

    .line 1
    iget v0, p0, Ld6/t0;->e:I

    .line 2
    .line 3
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x2

    .line 7
    iget-object v4, p0, Ld6/t0;->h:Ljava/lang/Object;

    .line 8
    .line 9
    const-string v5, "call to \'resume\' before \'invoke\' with coroutine"

    .line 10
    .line 11
    const/4 v6, 0x1

    .line 12
    packed-switch v0, :pswitch_data_0

    .line 13
    .line 14
    .line 15
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 16
    .line 17
    iget v1, p0, Ld6/t0;->f:I

    .line 18
    .line 19
    if-eqz v1, :cond_1

    .line 20
    .line 21
    if-ne v1, v6, :cond_0

    .line 22
    .line 23
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    throw p0

    .line 33
    :cond_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 34
    .line 35
    .line 36
    iget-object p1, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p1, Lp3/i0;

    .line 39
    .line 40
    check-cast v4, Lp3/l;

    .line 41
    .line 42
    iput v6, p0, Ld6/t0;->f:I

    .line 43
    .line 44
    invoke-static {p1, v4, p0}, Lg1/g3;->i(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p1

    .line 48
    if-ne p1, v0, :cond_2

    .line 49
    .line 50
    move-object p1, v0

    .line 51
    :cond_2
    :goto_0
    return-object p1

    .line 52
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 53
    .line 54
    iget v7, p0, Ld6/t0;->f:I

    .line 55
    .line 56
    if-eqz v7, :cond_5

    .line 57
    .line 58
    if-eq v7, v6, :cond_4

    .line 59
    .line 60
    if-ne v7, v3, :cond_3

    .line 61
    .line 62
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    goto :goto_3

    .line 66
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 67
    .line 68
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw p0

    .line 72
    :cond_4
    iget-object v5, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 73
    .line 74
    check-cast v5, Lp3/i0;

    .line 75
    .line 76
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 77
    .line 78
    .line 79
    goto :goto_1

    .line 80
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    iget-object p1, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 84
    .line 85
    move-object v5, p1

    .line 86
    check-cast v5, Lp3/i0;

    .line 87
    .line 88
    sget-object p1, Lp3/l;->d:Lp3/l;

    .line 89
    .line 90
    iput-object v5, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 91
    .line 92
    iput v6, p0, Ld6/t0;->f:I

    .line 93
    .line 94
    invoke-static {v5, p0, v6}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    if-ne p1, v0, :cond_6

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_6
    :goto_1
    check-cast p1, Lp3/t;

    .line 102
    .line 103
    sget-object p1, Lp3/l;->d:Lp3/l;

    .line 104
    .line 105
    iput-object v2, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 106
    .line 107
    iput v3, p0, Ld6/t0;->f:I

    .line 108
    .line 109
    invoke-static {v5, p1, p0}, Lg1/g3;->i(Lp3/i0;Lp3/l;Lrx0/a;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    if-ne p1, v0, :cond_7

    .line 114
    .line 115
    :goto_2
    move-object v1, v0

    .line 116
    goto :goto_4

    .line 117
    :cond_7
    :goto_3
    check-cast p1, Lp3/t;

    .line 118
    .line 119
    if-eqz p1, :cond_8

    .line 120
    .line 121
    check-cast v4, Lb71/o;

    .line 122
    .line 123
    invoke-virtual {v4}, Lb71/o;->invoke()Ljava/lang/Object;

    .line 124
    .line 125
    .line 126
    :cond_8
    :goto_4
    return-object v1

    .line 127
    :pswitch_1
    move-object v0, v4

    .line 128
    check-cast v0, Le1/j;

    .line 129
    .line 130
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 131
    .line 132
    iget v4, p0, Ld6/t0;->f:I

    .line 133
    .line 134
    if-eqz v4, :cond_b

    .line 135
    .line 136
    if-eq v4, v6, :cond_a

    .line 137
    .line 138
    if-ne v4, v3, :cond_9

    .line 139
    .line 140
    iget-object v4, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 141
    .line 142
    check-cast v4, Lp3/i0;

    .line 143
    .line 144
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    goto :goto_7

    .line 148
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 149
    .line 150
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    throw p0

    .line 154
    :cond_a
    iget-object v4, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast v4, Lp3/i0;

    .line 157
    .line 158
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    goto :goto_5

    .line 162
    :cond_b
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    iget-object p1, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 166
    .line 167
    move-object v4, p1

    .line 168
    check-cast v4, Lp3/i0;

    .line 169
    .line 170
    iput-object v4, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 171
    .line 172
    iput v6, p0, Ld6/t0;->f:I

    .line 173
    .line 174
    invoke-static {v4, p0, v3}, Lg1/g3;->c(Lp3/i0;Lkotlin/coroutines/Continuation;I)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object p1

    .line 178
    if-ne p1, v7, :cond_c

    .line 179
    .line 180
    goto :goto_6

    .line 181
    :cond_c
    :goto_5
    check-cast p1, Lp3/t;

    .line 182
    .line 183
    iget-wide v5, p1, Lp3/t;->a:J

    .line 184
    .line 185
    iput-wide v5, v0, Le1/j;->h:J

    .line 186
    .line 187
    iget-wide v5, p1, Lp3/t;->c:J

    .line 188
    .line 189
    iput-wide v5, v0, Le1/j;->b:J

    .line 190
    .line 191
    :cond_d
    iput-object v4, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 192
    .line 193
    iput v3, p0, Ld6/t0;->f:I

    .line 194
    .line 195
    sget-object p1, Lp3/l;->e:Lp3/l;

    .line 196
    .line 197
    invoke-virtual {v4, p1, p0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    move-result-object p1

    .line 201
    if-ne p1, v7, :cond_e

    .line 202
    .line 203
    :goto_6
    move-object v1, v7

    .line 204
    goto :goto_b

    .line 205
    :cond_e
    :goto_7
    check-cast p1, Lp3/k;

    .line 206
    .line 207
    iget-object p1, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 208
    .line 209
    new-instance v5, Ljava/util/ArrayList;

    .line 210
    .line 211
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 212
    .line 213
    .line 214
    move-result v6

    .line 215
    invoke-direct {v5, v6}, Ljava/util/ArrayList;-><init>(I)V

    .line 216
    .line 217
    .line 218
    move-object v6, p1

    .line 219
    check-cast v6, Ljava/util/Collection;

    .line 220
    .line 221
    invoke-interface {v6}, Ljava/util/Collection;->size()I

    .line 222
    .line 223
    .line 224
    move-result v6

    .line 225
    const/4 v8, 0x0

    .line 226
    move v9, v8

    .line 227
    :goto_8
    if-ge v9, v6, :cond_10

    .line 228
    .line 229
    invoke-interface {p1, v9}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object v10

    .line 233
    move-object v11, v10

    .line 234
    check-cast v11, Lp3/t;

    .line 235
    .line 236
    iget-boolean v11, v11, Lp3/t;->d:Z

    .line 237
    .line 238
    if-eqz v11, :cond_f

    .line 239
    .line 240
    invoke-virtual {v5, v10}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 241
    .line 242
    .line 243
    :cond_f
    add-int/lit8 v9, v9, 0x1

    .line 244
    .line 245
    goto :goto_8

    .line 246
    :cond_10
    invoke-virtual {v5}, Ljava/util/ArrayList;->size()I

    .line 247
    .line 248
    .line 249
    move-result p1

    .line 250
    :goto_9
    if-ge v8, p1, :cond_12

    .line 251
    .line 252
    invoke-virtual {v5, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    .line 253
    .line 254
    .line 255
    move-result-object v6

    .line 256
    move-object v9, v6

    .line 257
    check-cast v9, Lp3/t;

    .line 258
    .line 259
    iget-wide v9, v9, Lp3/t;->a:J

    .line 260
    .line 261
    iget-wide v11, v0, Le1/j;->h:J

    .line 262
    .line 263
    invoke-static {v9, v10, v11, v12}, Lp3/s;->e(JJ)Z

    .line 264
    .line 265
    .line 266
    move-result v9

    .line 267
    if-eqz v9, :cond_11

    .line 268
    .line 269
    goto :goto_a

    .line 270
    :cond_11
    add-int/lit8 v8, v8, 0x1

    .line 271
    .line 272
    goto :goto_9

    .line 273
    :cond_12
    move-object v6, v2

    .line 274
    :goto_a
    check-cast v6, Lp3/t;

    .line 275
    .line 276
    if-nez v6, :cond_13

    .line 277
    .line 278
    invoke-static {v5}, Lmx0/q;->L(Ljava/util/List;)Ljava/lang/Object;

    .line 279
    .line 280
    .line 281
    move-result-object p1

    .line 282
    move-object v6, p1

    .line 283
    check-cast v6, Lp3/t;

    .line 284
    .line 285
    :cond_13
    if-eqz v6, :cond_14

    .line 286
    .line 287
    iget-wide v8, v6, Lp3/t;->a:J

    .line 288
    .line 289
    iput-wide v8, v0, Le1/j;->h:J

    .line 290
    .line 291
    iget-wide v8, v6, Lp3/t;->c:J

    .line 292
    .line 293
    iput-wide v8, v0, Le1/j;->b:J

    .line 294
    .line 295
    :cond_14
    invoke-virtual {v5}, Ljava/util/ArrayList;->isEmpty()Z

    .line 296
    .line 297
    .line 298
    move-result p1

    .line 299
    if-eqz p1, :cond_d

    .line 300
    .line 301
    const-wide/16 p0, -0x1

    .line 302
    .line 303
    iput-wide p0, v0, Le1/j;->h:J

    .line 304
    .line 305
    :goto_b
    return-object v1

    .line 306
    :pswitch_2
    check-cast v4, Landroid/view/View;

    .line 307
    .line 308
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 309
    .line 310
    iget v7, p0, Ld6/t0;->f:I

    .line 311
    .line 312
    if-eqz v7, :cond_19

    .line 313
    .line 314
    if-eq v7, v6, :cond_16

    .line 315
    .line 316
    if-ne v7, v3, :cond_15

    .line 317
    .line 318
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 319
    .line 320
    .line 321
    goto :goto_f

    .line 322
    :cond_15
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 323
    .line 324
    invoke-direct {p0, v5}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 325
    .line 326
    .line 327
    throw p0

    .line 328
    :cond_16
    iget-object v5, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 329
    .line 330
    check-cast v5, Lky0/k;

    .line 331
    .line 332
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 333
    .line 334
    .line 335
    instance-of p1, v4, Landroid/view/ViewGroup;

    .line 336
    .line 337
    if-eqz p1, :cond_1a

    .line 338
    .line 339
    check-cast v4, Landroid/view/ViewGroup;

    .line 340
    .line 341
    iput-object v2, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 342
    .line 343
    iput v3, p0, Ld6/t0;->f:I

    .line 344
    .line 345
    invoke-virtual {v5}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 346
    .line 347
    .line 348
    new-instance p1, Ld6/b0;

    .line 349
    .line 350
    new-instance v2, Landroidx/collection/d1;

    .line 351
    .line 352
    invoke-direct {v2, v4, v6}, Landroidx/collection/d1;-><init>(Ljava/lang/Object;I)V

    .line 353
    .line 354
    .line 355
    invoke-direct {p1, v2}, Ld6/b0;-><init>(Landroidx/collection/d1;)V

    .line 356
    .line 357
    .line 358
    iget-object v2, p1, Ld6/b0;->e:Ljava/util/Iterator;

    .line 359
    .line 360
    invoke-interface {v2}, Ljava/util/Iterator;->hasNext()Z

    .line 361
    .line 362
    .line 363
    move-result v2

    .line 364
    if-nez v2, :cond_17

    .line 365
    .line 366
    move-object p0, v1

    .line 367
    goto :goto_c

    .line 368
    :cond_17
    iput-object p1, v5, Lky0/k;->f:Ljava/util/Iterator;

    .line 369
    .line 370
    iput v3, v5, Lky0/k;->d:I

    .line 371
    .line 372
    iput-object p0, v5, Lky0/k;->g:Lkotlin/coroutines/Continuation;

    .line 373
    .line 374
    move-object p0, v0

    .line 375
    :goto_c
    if-ne p0, v0, :cond_18

    .line 376
    .line 377
    goto :goto_d

    .line 378
    :cond_18
    move-object p0, v1

    .line 379
    :goto_d
    if-ne p0, v0, :cond_1a

    .line 380
    .line 381
    :goto_e
    move-object v1, v0

    .line 382
    goto :goto_f

    .line 383
    :cond_19
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 384
    .line 385
    .line 386
    iget-object p1, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 387
    .line 388
    check-cast p1, Lky0/k;

    .line 389
    .line 390
    iput-object p1, p0, Ld6/t0;->g:Ljava/lang/Object;

    .line 391
    .line 392
    iput v6, p0, Ld6/t0;->f:I

    .line 393
    .line 394
    invoke-virtual {p1, v4, p0}, Lky0/k;->b(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 395
    .line 396
    .line 397
    goto :goto_e

    .line 398
    :cond_1a
    :goto_f
    return-object v1

    .line 399
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
