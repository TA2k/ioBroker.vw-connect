.class public final Lfw0/x;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/o;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public synthetic f:Ljava/lang/Object;

.field public final synthetic g:Ljava/lang/Object;

.field public final synthetic h:Ljava/lang/Object;


# direct methods
.method public synthetic constructor <init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V
    .locals 0

    .line 1
    iput p1, p0, Lfw0/x;->d:I

    .line 2
    .line 3
    iput-object p2, p0, Lfw0/x;->g:Ljava/lang/Object;

    .line 4
    .line 5
    iput-object p3, p0, Lfw0/x;->h:Ljava/lang/Object;

    .line 6
    .line 7
    const/4 p1, 0x3

    .line 8
    invoke-direct {p0, p1, p4}, Lrx0/i;-><init>(ILkotlin/coroutines/Continuation;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 3

    .line 1
    iget v0, p0, Lfw0/x;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lne0/t;

    .line 7
    .line 8
    check-cast p2, Lqp0/r;

    .line 9
    .line 10
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    new-instance v0, Lfw0/x;

    .line 13
    .line 14
    iget-object v1, p0, Lfw0/x;->g:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v1, Lzy/p;

    .line 17
    .line 18
    iget-object p0, p0, Lfw0/x;->h:Ljava/lang/Object;

    .line 19
    .line 20
    check-cast p0, Laz/i;

    .line 21
    .line 22
    const/4 v2, 0x2

    .line 23
    invoke-direct {v0, v2, v1, p0, p3}, Lfw0/x;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 24
    .line 25
    .line 26
    iput-object p1, v0, Lfw0/x;->e:Ljava/lang/Object;

    .line 27
    .line 28
    iput-object p2, v0, Lfw0/x;->f:Ljava/lang/Object;

    .line 29
    .line 30
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 31
    .line 32
    invoke-virtual {v0, p0}, Lfw0/x;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object p0

    .line 36
    return-object p0

    .line 37
    :pswitch_0
    check-cast p1, Lrd0/j;

    .line 38
    .line 39
    check-cast p2, Lmm0/a;

    .line 40
    .line 41
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 42
    .line 43
    new-instance v0, Lfw0/x;

    .line 44
    .line 45
    iget-object v1, p0, Lfw0/x;->g:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast v1, Lru0/p;

    .line 48
    .line 49
    iget-object p0, p0, Lfw0/x;->h:Ljava/lang/Object;

    .line 50
    .line 51
    check-cast p0, Lss0/k;

    .line 52
    .line 53
    const/4 v2, 0x1

    .line 54
    invoke-direct {v0, v2, v1, p0, p3}, Lfw0/x;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 55
    .line 56
    .line 57
    iput-object p1, v0, Lfw0/x;->e:Ljava/lang/Object;

    .line 58
    .line 59
    iput-object p2, v0, Lfw0/x;->f:Ljava/lang/Object;

    .line 60
    .line 61
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 62
    .line 63
    invoke-virtual {v0, p0}, Lfw0/x;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    :pswitch_1
    check-cast p1, Lkw0/c;

    .line 69
    .line 70
    check-cast p3, Lkotlin/coroutines/Continuation;

    .line 71
    .line 72
    new-instance v0, Lfw0/x;

    .line 73
    .line 74
    iget-object v1, p0, Lfw0/x;->g:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast v1, Ljava/lang/String;

    .line 77
    .line 78
    iget-object p0, p0, Lfw0/x;->h:Ljava/lang/Object;

    .line 79
    .line 80
    check-cast p0, Ljava/nio/charset/Charset;

    .line 81
    .line 82
    const/4 v2, 0x0

    .line 83
    invoke-direct {v0, v2, v1, p0, p3}, Lfw0/x;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 84
    .line 85
    .line 86
    iput-object p1, v0, Lfw0/x;->e:Ljava/lang/Object;

    .line 87
    .line 88
    iput-object p2, v0, Lfw0/x;->f:Ljava/lang/Object;

    .line 89
    .line 90
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 91
    .line 92
    invoke-virtual {v0, p0}, Lfw0/x;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    return-object p0

    .line 97
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 8

    .line 1
    iget v0, p0, Lfw0/x;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lfw0/x;->g:Ljava/lang/Object;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    iget-object v3, p0, Lfw0/x;->h:Ljava/lang/Object;

    .line 7
    .line 8
    packed-switch v0, :pswitch_data_0

    .line 9
    .line 10
    .line 11
    check-cast v3, Laz/i;

    .line 12
    .line 13
    check-cast v1, Lzy/p;

    .line 14
    .line 15
    iget-object v0, v1, Lzy/p;->c:Lxy/g;

    .line 16
    .line 17
    iget-object v1, p0, Lfw0/x;->e:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast v1, Lne0/t;

    .line 20
    .line 21
    iget-object p0, p0, Lfw0/x;->f:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lqp0/r;

    .line 24
    .line 25
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 26
    .line 27
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    instance-of p1, v1, Lne0/e;

    .line 31
    .line 32
    if-eqz p1, :cond_0

    .line 33
    .line 34
    check-cast v1, Lne0/e;

    .line 35
    .line 36
    iget-object p1, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast p1, Lss0/j0;

    .line 39
    .line 40
    iget-object p1, p1, Lss0/j0;->d:Ljava/lang/String;

    .line 41
    .line 42
    invoke-virtual {v0, v3, p1, p0}, Lxy/g;->a(Laz/i;Ljava/lang/String;Lqp0/r;)Lyy0/m1;

    .line 43
    .line 44
    .line 45
    move-result-object p0

    .line 46
    goto :goto_0

    .line 47
    :cond_0
    invoke-virtual {v0, v3, v2, p0}, Lxy/g;->a(Laz/i;Ljava/lang/String;Lqp0/r;)Lyy0/m1;

    .line 48
    .line 49
    .line 50
    move-result-object p0

    .line 51
    :goto_0
    return-object p0

    .line 52
    :pswitch_0
    iget-object v0, p0, Lfw0/x;->e:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast v0, Lrd0/j;

    .line 55
    .line 56
    iget-object p0, p0, Lfw0/x;->f:Ljava/lang/Object;

    .line 57
    .line 58
    check-cast p0, Lmm0/a;

    .line 59
    .line 60
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 61
    .line 62
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    if-eqz v0, :cond_1

    .line 66
    .line 67
    iget-object p1, v0, Lrd0/j;->d:Lrd0/a0;

    .line 68
    .line 69
    if-eqz p1, :cond_1

    .line 70
    .line 71
    iget-object p1, p1, Lrd0/a0;->a:Lrd0/y;

    .line 72
    .line 73
    goto :goto_1

    .line 74
    :cond_1
    move-object p1, v2

    .line 75
    :goto_1
    if-nez p1, :cond_2

    .line 76
    .line 77
    const/4 p1, -0x1

    .line 78
    goto :goto_2

    .line 79
    :cond_2
    sget-object v0, Lru0/n;->a:[I

    .line 80
    .line 81
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 82
    .line 83
    .line 84
    move-result p1

    .line 85
    aget p1, v0, p1

    .line 86
    .line 87
    :goto_2
    const/4 v0, 0x1

    .line 88
    if-eq p1, v0, :cond_5

    .line 89
    .line 90
    const/4 v0, 0x2

    .line 91
    if-eq p1, v0, :cond_5

    .line 92
    .line 93
    const/4 v0, 0x3

    .line 94
    if-eq p1, v0, :cond_3

    .line 95
    .line 96
    sget-object p0, Lhp0/d;->e:Lhp0/d;

    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_3
    sget-object p1, Lmm0/a;->e:Lmm0/a;

    .line 100
    .line 101
    if-ne p0, p1, :cond_4

    .line 102
    .line 103
    sget-object p0, Lhp0/d;->p:Lhp0/d;

    .line 104
    .line 105
    goto :goto_3

    .line 106
    :cond_4
    sget-object p0, Lhp0/d;->o:Lhp0/d;

    .line 107
    .line 108
    goto :goto_3

    .line 109
    :cond_5
    sget-object p1, Lmm0/a;->e:Lmm0/a;

    .line 110
    .line 111
    if-ne p0, p1, :cond_6

    .line 112
    .line 113
    sget-object p0, Lhp0/d;->n:Lhp0/d;

    .line 114
    .line 115
    goto :goto_3

    .line 116
    :cond_6
    sget-object p0, Lhp0/d;->m:Lhp0/d;

    .line 117
    .line 118
    :goto_3
    check-cast v3, Lss0/k;

    .line 119
    .line 120
    if-eqz v3, :cond_9

    .line 121
    .line 122
    iget-object p1, v3, Lss0/k;->g:Ljava/util/List;

    .line 123
    .line 124
    check-cast p1, Ljava/lang/Iterable;

    .line 125
    .line 126
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 127
    .line 128
    .line 129
    move-result-object p1

    .line 130
    :cond_7
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 131
    .line 132
    .line 133
    move-result v0

    .line 134
    if-eqz v0, :cond_8

    .line 135
    .line 136
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 137
    .line 138
    .line 139
    move-result-object v0

    .line 140
    move-object v1, v0

    .line 141
    check-cast v1, Lhp0/e;

    .line 142
    .line 143
    iget-object v1, v1, Lhp0/e;->c:Lhp0/d;

    .line 144
    .line 145
    if-ne v1, p0, :cond_7

    .line 146
    .line 147
    move-object v2, v0

    .line 148
    :cond_8
    check-cast v2, Lhp0/e;

    .line 149
    .line 150
    :cond_9
    return-object v2

    .line 151
    :pswitch_1
    iget-object v0, p0, Lfw0/x;->e:Ljava/lang/Object;

    .line 152
    .line 153
    check-cast v0, Lkw0/c;

    .line 154
    .line 155
    iget-object p0, p0, Lfw0/x;->f:Ljava/lang/Object;

    .line 156
    .line 157
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 158
    .line 159
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 160
    .line 161
    .line 162
    check-cast v1, Ljava/lang/String;

    .line 163
    .line 164
    sget-object p1, Lfw0/a0;->a:Lt21/b;

    .line 165
    .line 166
    iget-object p1, v0, Lkw0/c;->c:Low0/n;

    .line 167
    .line 168
    iget-object v4, v0, Lkw0/c;->a:Low0/z;

    .line 169
    .line 170
    sget-object v5, Low0/q;->a:Ljava/util/List;

    .line 171
    .line 172
    const-string v5, "Accept-Charset"

    .line 173
    .line 174
    invoke-virtual {p1, v5}, Lap0/o;->z(Ljava/lang/String;)Ljava/lang/String;

    .line 175
    .line 176
    .line 177
    move-result-object p1

    .line 178
    if-eqz p1, :cond_a

    .line 179
    .line 180
    goto :goto_4

    .line 181
    :cond_a
    sget-object p1, Lfw0/a0;->a:Lt21/b;

    .line 182
    .line 183
    new-instance v6, Ljava/lang/StringBuilder;

    .line 184
    .line 185
    const-string v7, "Adding Accept-Charset="

    .line 186
    .line 187
    invoke-direct {v6, v7}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {v6, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 191
    .line 192
    .line 193
    const-string v7, " to "

    .line 194
    .line 195
    invoke-virtual {v6, v7}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    invoke-virtual {v6, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 199
    .line 200
    .line 201
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 202
    .line 203
    .line 204
    move-result-object v6

    .line 205
    invoke-interface {p1, v6}, Lt21/b;->h(Ljava/lang/String;)V

    .line 206
    .line 207
    .line 208
    iget-object p1, v0, Lkw0/c;->c:Low0/n;

    .line 209
    .line 210
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 211
    .line 212
    .line 213
    const-string v6, "value"

    .line 214
    .line 215
    invoke-static {v1, v6}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 216
    .line 217
    .line 218
    invoke-virtual {p1, v1}, Low0/n;->Z(Ljava/lang/String;)V

    .line 219
    .line 220
    .line 221
    invoke-virtual {p1, v5}, Lap0/o;->w(Ljava/lang/String;)Ljava/util/List;

    .line 222
    .line 223
    .line 224
    move-result-object p1

    .line 225
    invoke-interface {p1}, Ljava/util/List;->clear()V

    .line 226
    .line 227
    .line 228
    invoke-interface {p1, v1}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 229
    .line 230
    .line 231
    :goto_4
    instance-of p1, p0, Ljava/lang/String;

    .line 232
    .line 233
    if-nez p1, :cond_b

    .line 234
    .line 235
    goto :goto_7

    .line 236
    :cond_b
    invoke-static {v0}, Ljp/pc;->c(Lkw0/c;)Low0/e;

    .line 237
    .line 238
    .line 239
    move-result-object p1

    .line 240
    if-eqz p1, :cond_c

    .line 241
    .line 242
    iget-object v0, p1, Low0/e;->d:Ljava/lang/String;

    .line 243
    .line 244
    sget-object v1, Low0/d;->a:Low0/e;

    .line 245
    .line 246
    iget-object v1, v1, Low0/e;->d:Ljava/lang/String;

    .line 247
    .line 248
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 249
    .line 250
    .line 251
    move-result v0

    .line 252
    if-nez v0, :cond_c

    .line 253
    .line 254
    goto :goto_7

    .line 255
    :cond_c
    check-cast v3, Ljava/nio/charset/Charset;

    .line 256
    .line 257
    check-cast p0, Ljava/lang/String;

    .line 258
    .line 259
    if-nez p1, :cond_d

    .line 260
    .line 261
    sget-object v0, Low0/d;->a:Low0/e;

    .line 262
    .line 263
    goto :goto_5

    .line 264
    :cond_d
    move-object v0, p1

    .line 265
    :goto_5
    if-eqz p1, :cond_f

    .line 266
    .line 267
    invoke-static {p1}, Ljp/ic;->e(Low0/e;)Ljava/nio/charset/Charset;

    .line 268
    .line 269
    .line 270
    move-result-object p1

    .line 271
    if-nez p1, :cond_e

    .line 272
    .line 273
    goto :goto_6

    .line 274
    :cond_e
    move-object v3, p1

    .line 275
    :cond_f
    :goto_6
    sget-object p1, Lfw0/a0;->a:Lt21/b;

    .line 276
    .line 277
    new-instance v1, Ljava/lang/StringBuilder;

    .line 278
    .line 279
    const-string v2, "Sending request body to "

    .line 280
    .line 281
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 282
    .line 283
    .line 284
    invoke-virtual {v1, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 285
    .line 286
    .line 287
    const-string v2, " as text/plain with charset "

    .line 288
    .line 289
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 290
    .line 291
    .line 292
    invoke-virtual {v1, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 293
    .line 294
    .line 295
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 296
    .line 297
    .line 298
    move-result-object v1

    .line 299
    invoke-interface {p1, v1}, Lt21/b;->h(Ljava/lang/String;)V

    .line 300
    .line 301
    .line 302
    new-instance v2, Lrw0/e;

    .line 303
    .line 304
    const-string p1, "<this>"

    .line 305
    .line 306
    invoke-static {v0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 307
    .line 308
    .line 309
    const-string p1, "charset"

    .line 310
    .line 311
    invoke-static {v3, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 312
    .line 313
    .line 314
    invoke-static {v3}, Ljp/q1;->c(Ljava/nio/charset/Charset;)Ljava/lang/String;

    .line 315
    .line 316
    .line 317
    move-result-object p1

    .line 318
    invoke-virtual {v0, p1}, Low0/e;->r(Ljava/lang/String;)Low0/e;

    .line 319
    .line 320
    .line 321
    move-result-object p1

    .line 322
    invoke-direct {v2, p0, p1}, Lrw0/e;-><init>(Ljava/lang/String;Low0/e;)V

    .line 323
    .line 324
    .line 325
    :goto_7
    return-object v2

    .line 326
    nop

    .line 327
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
