.class public final Lok0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lfg0/d;

.field public final b:Lml0/i;

.field public final c:Lfg0/a;

.field public final d:Lwj0/j0;


# direct methods
.method public constructor <init>(Lfg0/d;Lml0/i;Lfg0/a;Lwj0/j0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lok0/l;->a:Lfg0/d;

    .line 5
    .line 6
    iput-object p2, p0, Lok0/l;->b:Lml0/i;

    .line 7
    .line 8
    iput-object p3, p0, Lok0/l;->c:Lfg0/a;

    .line 9
    .line 10
    iput-object p4, p0, Lok0/l;->d:Lwj0/j0;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lpk0/a;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lok0/l;->c(Lpk0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lok0/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lok0/h;

    .line 7
    .line 8
    iget v1, v0, Lok0/h;->f:I

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
    iput v1, v0, Lok0/h;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lok0/h;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lok0/h;-><init>(Lok0/l;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lok0/h;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lok0/h;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    if-eqz v2, :cond_2

    .line 33
    .line 34
    if-ne v2, v3, :cond_1

    .line 35
    .line 36
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_1
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
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    iget-object p0, p0, Lok0/l;->a:Lfg0/d;

    .line 52
    .line 53
    invoke-virtual {p0}, Lfg0/d;->invoke()Ljava/lang/Object;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    check-cast p0, Lyy0/i;

    .line 58
    .line 59
    iput v3, v0, Lok0/h;->f:I

    .line 60
    .line 61
    invoke-static {p0, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p1

    .line 65
    if-ne p1, v1, :cond_3

    .line 66
    .line 67
    return-object v1

    .line 68
    :cond_3
    :goto_1
    check-cast p1, Lgg0/a;

    .line 69
    .line 70
    if-eqz p1, :cond_4

    .line 71
    .line 72
    new-instance p0, Lxj0/f;

    .line 73
    .line 74
    iget-wide v0, p1, Lgg0/a;->a:D

    .line 75
    .line 76
    iget-wide v2, p1, Lgg0/a;->b:D

    .line 77
    .line 78
    invoke-direct {p0, v0, v1, v2, v3}, Lxj0/f;-><init>(DD)V

    .line 79
    .line 80
    .line 81
    return-object p0

    .line 82
    :cond_4
    const/4 p0, 0x0

    .line 83
    return-object p0
.end method

.method public final c(Lpk0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Lok0/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lok0/k;

    .line 7
    .line 8
    iget v1, v0, Lok0/k;->j:I

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
    iput v1, v0, Lok0/k;->j:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lok0/k;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lok0/k;-><init>(Lok0/l;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lok0/k;->h:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lok0/k;->j:I

    .line 30
    .line 31
    iget-object v3, p0, Lok0/l;->b:Lml0/i;

    .line 32
    .line 33
    const/4 v4, 0x4

    .line 34
    const/4 v5, 0x2

    .line 35
    const/4 v6, 0x3

    .line 36
    const/4 v7, 0x1

    .line 37
    const/4 v8, 0x0

    .line 38
    if-eqz v2, :cond_5

    .line 39
    .line 40
    if-eq v2, v7, :cond_4

    .line 41
    .line 42
    if-eq v2, v5, :cond_3

    .line 43
    .line 44
    if-eq v2, v6, :cond_2

    .line 45
    .line 46
    if-ne v2, v4, :cond_1

    .line 47
    .line 48
    iget-object p1, v0, Lok0/k;->f:Ljava/util/List;

    .line 49
    .line 50
    check-cast p1, Ljava/util/List;

    .line 51
    .line 52
    iget-object v0, v0, Lok0/k;->d:Ljava/util/List;

    .line 53
    .line 54
    check-cast v0, Ljava/util/List;

    .line 55
    .line 56
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto/16 :goto_1

    .line 60
    .line 61
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 64
    .line 65
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :cond_2
    iget-object p1, v0, Lok0/k;->f:Ljava/util/List;

    .line 70
    .line 71
    check-cast p1, Ljava/util/List;

    .line 72
    .line 73
    iget-object v0, v0, Lok0/k;->d:Ljava/util/List;

    .line 74
    .line 75
    check-cast v0, Ljava/util/List;

    .line 76
    .line 77
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    goto/16 :goto_3

    .line 81
    .line 82
    :cond_3
    iget-object p1, v0, Lok0/k;->f:Ljava/util/List;

    .line 83
    .line 84
    check-cast p1, Ljava/util/List;

    .line 85
    .line 86
    iget-object v0, v0, Lok0/k;->d:Ljava/util/List;

    .line 87
    .line 88
    check-cast v0, Ljava/util/List;

    .line 89
    .line 90
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    goto/16 :goto_6

    .line 94
    .line 95
    :cond_4
    iget p1, v0, Lok0/k;->g:I

    .line 96
    .line 97
    iget-object v2, v0, Lok0/k;->f:Ljava/util/List;

    .line 98
    .line 99
    check-cast v2, Ljava/util/List;

    .line 100
    .line 101
    iget-object v4, v0, Lok0/k;->e:Lnx0/c;

    .line 102
    .line 103
    iget-object v6, v0, Lok0/k;->d:Ljava/util/List;

    .line 104
    .line 105
    check-cast v6, Ljava/util/List;

    .line 106
    .line 107
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    move-object v9, v2

    .line 111
    move v2, p1

    .line 112
    move-object p1, v4

    .line 113
    move-object v4, v9

    .line 114
    goto/16 :goto_4

    .line 115
    .line 116
    :cond_5
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 117
    .line 118
    .line 119
    invoke-static {}, Ljp/k1;->f()Lnx0/c;

    .line 120
    .line 121
    .line 122
    move-result-object p2

    .line 123
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 124
    .line 125
    .line 126
    move-result p1

    .line 127
    const/4 v2, 0x0

    .line 128
    if-eqz p1, :cond_b

    .line 129
    .line 130
    if-eq p1, v7, :cond_9

    .line 131
    .line 132
    if-eq p1, v6, :cond_8

    .line 133
    .line 134
    const/4 v5, 0x5

    .line 135
    if-eq p1, v5, :cond_6

    .line 136
    .line 137
    goto/16 :goto_7

    .line 138
    .line 139
    :cond_6
    iput-object p2, v0, Lok0/k;->d:Ljava/util/List;

    .line 140
    .line 141
    iput-object v8, v0, Lok0/k;->e:Lnx0/c;

    .line 142
    .line 143
    iput-object p2, v0, Lok0/k;->f:Ljava/util/List;

    .line 144
    .line 145
    iput v2, v0, Lok0/k;->g:I

    .line 146
    .line 147
    iput v4, v0, Lok0/k;->j:I

    .line 148
    .line 149
    invoke-virtual {v3}, Lml0/i;->invoke()Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    check-cast p1, Lyy0/i;

    .line 154
    .line 155
    new-instance v2, Lhg/q;

    .line 156
    .line 157
    const/16 v3, 0x16

    .line 158
    .line 159
    invoke-direct {v2, p1, v3}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 160
    .line 161
    .line 162
    new-instance p1, Lam0/i;

    .line 163
    .line 164
    const/16 v3, 0x13

    .line 165
    .line 166
    invoke-direct {p1, v2, v3}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 167
    .line 168
    .line 169
    invoke-static {p1, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 170
    .line 171
    .line 172
    move-result-object p1

    .line 173
    if-ne p1, v1, :cond_7

    .line 174
    .line 175
    goto/16 :goto_5

    .line 176
    .line 177
    :cond_7
    move-object v0, p2

    .line 178
    move-object p2, p1

    .line 179
    move-object p1, v0

    .line 180
    :goto_1
    invoke-interface {p1, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 181
    .line 182
    .line 183
    :goto_2
    move-object p2, v0

    .line 184
    goto/16 :goto_7

    .line 185
    .line 186
    :cond_8
    iget-object p1, p0, Lok0/l;->c:Lfg0/a;

    .line 187
    .line 188
    invoke-virtual {p1}, Lfg0/a;->invoke()Ljava/lang/Object;

    .line 189
    .line 190
    .line 191
    goto :goto_7

    .line 192
    :cond_9
    iput-object p2, v0, Lok0/k;->d:Ljava/util/List;

    .line 193
    .line 194
    iput-object v8, v0, Lok0/k;->e:Lnx0/c;

    .line 195
    .line 196
    iput-object p2, v0, Lok0/k;->f:Ljava/util/List;

    .line 197
    .line 198
    iput v2, v0, Lok0/k;->g:I

    .line 199
    .line 200
    iput v6, v0, Lok0/k;->j:I

    .line 201
    .line 202
    invoke-virtual {p0, v0}, Lok0/l;->b(Lrx0/c;)Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    move-result-object p1

    .line 206
    if-ne p1, v1, :cond_a

    .line 207
    .line 208
    goto :goto_5

    .line 209
    :cond_a
    move-object v0, p2

    .line 210
    move-object p2, p1

    .line 211
    move-object p1, v0

    .line 212
    :goto_3
    invoke-interface {p1, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 213
    .line 214
    .line 215
    goto :goto_2

    .line 216
    :cond_b
    iput-object p2, v0, Lok0/k;->d:Ljava/util/List;

    .line 217
    .line 218
    iput-object p2, v0, Lok0/k;->e:Lnx0/c;

    .line 219
    .line 220
    iput-object p2, v0, Lok0/k;->f:Ljava/util/List;

    .line 221
    .line 222
    iput v2, v0, Lok0/k;->g:I

    .line 223
    .line 224
    iput v7, v0, Lok0/k;->j:I

    .line 225
    .line 226
    invoke-virtual {p0, v0}, Lok0/l;->b(Lrx0/c;)Ljava/lang/Object;

    .line 227
    .line 228
    .line 229
    move-result-object p1

    .line 230
    if-ne p1, v1, :cond_c

    .line 231
    .line 232
    goto :goto_5

    .line 233
    :cond_c
    move-object v4, p2

    .line 234
    move-object v6, v4

    .line 235
    move-object p2, p1

    .line 236
    move-object p1, v6

    .line 237
    :goto_4
    invoke-interface {v4, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 238
    .line 239
    .line 240
    move-object p2, v6

    .line 241
    check-cast p2, Ljava/util/List;

    .line 242
    .line 243
    iput-object p2, v0, Lok0/k;->d:Ljava/util/List;

    .line 244
    .line 245
    iput-object v8, v0, Lok0/k;->e:Lnx0/c;

    .line 246
    .line 247
    iput-object p1, v0, Lok0/k;->f:Ljava/util/List;

    .line 248
    .line 249
    iput v2, v0, Lok0/k;->g:I

    .line 250
    .line 251
    iput v5, v0, Lok0/k;->j:I

    .line 252
    .line 253
    invoke-virtual {v3}, Lml0/i;->invoke()Ljava/lang/Object;

    .line 254
    .line 255
    .line 256
    move-result-object p2

    .line 257
    check-cast p2, Lyy0/i;

    .line 258
    .line 259
    new-instance v2, Lhg/q;

    .line 260
    .line 261
    const/16 v3, 0x16

    .line 262
    .line 263
    invoke-direct {v2, p2, v3}, Lhg/q;-><init>(Lyy0/i;I)V

    .line 264
    .line 265
    .line 266
    new-instance p2, Lam0/i;

    .line 267
    .line 268
    const/16 v3, 0x13

    .line 269
    .line 270
    invoke-direct {p2, v2, v3}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 271
    .line 272
    .line 273
    invoke-static {p2, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 274
    .line 275
    .line 276
    move-result-object p2

    .line 277
    if-ne p2, v1, :cond_d

    .line 278
    .line 279
    :goto_5
    return-object v1

    .line 280
    :cond_d
    move-object v0, v6

    .line 281
    :goto_6
    invoke-interface {p1, p2}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 282
    .line 283
    .line 284
    goto :goto_2

    .line 285
    :goto_7
    invoke-static {p2}, Ljp/k1;->d(Ljava/util/List;)Lnx0/c;

    .line 286
    .line 287
    .line 288
    move-result-object p1

    .line 289
    invoke-static {p1}, Lmx0/q;->H(Ljava/lang/Iterable;)Ljava/util/ArrayList;

    .line 290
    .line 291
    .line 292
    move-result-object p1

    .line 293
    invoke-virtual {p1}, Ljava/util/ArrayList;->isEmpty()Z

    .line 294
    .line 295
    .line 296
    move-result p2

    .line 297
    if-nez p2, :cond_e

    .line 298
    .line 299
    iget-object p0, p0, Lok0/l;->d:Lwj0/j0;

    .line 300
    .line 301
    invoke-virtual {p0, p1}, Lwj0/j0;->a(Ljava/util/Collection;)V

    .line 302
    .line 303
    .line 304
    :cond_e
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 305
    .line 306
    return-object p0
.end method
