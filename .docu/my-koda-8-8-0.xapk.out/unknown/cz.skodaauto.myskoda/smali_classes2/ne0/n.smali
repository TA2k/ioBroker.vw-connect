.class public final Lne0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/i;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lrx0/i;

.field public final synthetic f:Lyy0/i;


# direct methods
.method public constructor <init>(Lay0/n;Lyy0/i;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lne0/n;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    check-cast p1, Lrx0/i;

    iput-object p1, p0, Lne0/n;->e:Lrx0/i;

    iput-object p2, p0, Lne0/n;->f:Lyy0/i;

    return-void
.end method

.method public constructor <init>(Lyy0/i;Lay0/k;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lne0/n;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Lne0/n;->f:Lyy0/i;

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lne0/n;->e:Lrx0/i;

    return-void
.end method

.method public constructor <init>(Lyy0/i;Lay0/n;I)V
    .locals 0

    iput p3, p0, Lne0/n;->d:I

    packed-switch p3, :pswitch_data_0

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    iput-object p1, p0, Lne0/n;->f:Lyy0/i;

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lne0/n;->e:Lrx0/i;

    return-void

    .line 7
    :pswitch_0
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-object p1, p0, Lne0/n;->f:Lyy0/i;

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lne0/n;->e:Lrx0/i;

    return-void

    .line 9
    :pswitch_1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 10
    iput-object p1, p0, Lne0/n;->f:Lyy0/i;

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lne0/n;->e:Lrx0/i;

    return-void

    nop

    :pswitch_data_0
    .packed-switch 0x4
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public constructor <init>(Lyy0/i;Lay0/o;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Lne0/n;->d:I

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    iput-object p1, p0, Lne0/n;->f:Lyy0/i;

    check-cast p2, Lrx0/i;

    iput-object p2, p0, Lne0/n;->e:Lrx0/i;

    return-void
.end method


# virtual methods
.method public final collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget v0, p0, Lne0/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lcn0/e;

    .line 7
    .line 8
    iget-object v1, p0, Lne0/n;->e:Lrx0/i;

    .line 9
    .line 10
    const/4 v2, 0x5

    .line 11
    invoke-direct {v0, p1, v1, v2}, Lcn0/e;-><init>(Lyy0/j;Lay0/n;I)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lne0/n;->f:Lyy0/i;

    .line 15
    .line 16
    invoke-interface {p0, v0, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 21
    .line 22
    if-ne p0, p1, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    :goto_0
    return-object p0

    .line 28
    :pswitch_0
    new-instance v0, Lcn0/e;

    .line 29
    .line 30
    iget-object v1, p0, Lne0/n;->e:Lrx0/i;

    .line 31
    .line 32
    const/4 v2, 0x4

    .line 33
    invoke-direct {v0, p1, v1, v2}, Lcn0/e;-><init>(Lyy0/j;Lay0/n;I)V

    .line 34
    .line 35
    .line 36
    iget-object p0, p0, Lne0/n;->f:Lyy0/i;

    .line 37
    .line 38
    invoke-interface {p0, v0, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 39
    .line 40
    .line 41
    move-result-object p0

    .line 42
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 43
    .line 44
    if-ne p0, p1, :cond_1

    .line 45
    .line 46
    goto :goto_1

    .line 47
    :cond_1
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    :goto_1
    return-object p0

    .line 50
    :pswitch_1
    new-instance v0, Lkotlin/jvm/internal/b0;

    .line 51
    .line 52
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 53
    .line 54
    .line 55
    new-instance v1, Laa/h0;

    .line 56
    .line 57
    iget-object v2, p0, Lne0/n;->e:Lrx0/i;

    .line 58
    .line 59
    invoke-direct {v1, v0, p1, v2}, Laa/h0;-><init>(Lkotlin/jvm/internal/b0;Lyy0/j;Lay0/n;)V

    .line 60
    .line 61
    .line 62
    iget-object p0, p0, Lne0/n;->f:Lyy0/i;

    .line 63
    .line 64
    invoke-interface {p0, v1, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 69
    .line 70
    if-ne p0, p1, :cond_2

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_2
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 74
    .line 75
    :goto_2
    return-object p0

    .line 76
    :pswitch_2
    instance-of v0, p2, Lyy0/z;

    .line 77
    .line 78
    if-eqz v0, :cond_3

    .line 79
    .line 80
    move-object v0, p2

    .line 81
    check-cast v0, Lyy0/z;

    .line 82
    .line 83
    iget v1, v0, Lyy0/z;->e:I

    .line 84
    .line 85
    const/high16 v2, -0x80000000

    .line 86
    .line 87
    and-int v3, v1, v2

    .line 88
    .line 89
    if-eqz v3, :cond_3

    .line 90
    .line 91
    sub-int/2addr v1, v2

    .line 92
    iput v1, v0, Lyy0/z;->e:I

    .line 93
    .line 94
    goto :goto_3

    .line 95
    :cond_3
    new-instance v0, Lyy0/z;

    .line 96
    .line 97
    invoke-direct {v0, p0, p2}, Lyy0/z;-><init>(Lne0/n;Lkotlin/coroutines/Continuation;)V

    .line 98
    .line 99
    .line 100
    :goto_3
    iget-object p2, v0, Lyy0/z;->d:Ljava/lang/Object;

    .line 101
    .line 102
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 103
    .line 104
    iget v2, v0, Lyy0/z;->e:I

    .line 105
    .line 106
    const/4 v3, 0x2

    .line 107
    const/4 v4, 0x1

    .line 108
    if-eqz v2, :cond_6

    .line 109
    .line 110
    if-eq v2, v4, :cond_5

    .line 111
    .line 112
    if-ne v2, v3, :cond_4

    .line 113
    .line 114
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 115
    .line 116
    .line 117
    goto :goto_5

    .line 118
    :cond_4
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 119
    .line 120
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 121
    .line 122
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 123
    .line 124
    .line 125
    throw p0

    .line 126
    :cond_5
    iget-object p1, v0, Lyy0/z;->h:Lyy0/j;

    .line 127
    .line 128
    iget-object p0, v0, Lyy0/z;->g:Lne0/n;

    .line 129
    .line 130
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 131
    .line 132
    .line 133
    goto :goto_4

    .line 134
    :cond_6
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 135
    .line 136
    .line 137
    iput-object p0, v0, Lyy0/z;->g:Lne0/n;

    .line 138
    .line 139
    iput-object p1, v0, Lyy0/z;->h:Lyy0/j;

    .line 140
    .line 141
    iput v4, v0, Lyy0/z;->e:I

    .line 142
    .line 143
    iget-object p2, p0, Lne0/n;->f:Lyy0/i;

    .line 144
    .line 145
    invoke-static {p2, p1, v0}, Lyy0/u;->i(Lyy0/i;Lyy0/j;Lrx0/c;)Ljava/io/Serializable;

    .line 146
    .line 147
    .line 148
    move-result-object p2

    .line 149
    if-ne p2, v1, :cond_7

    .line 150
    .line 151
    goto :goto_6

    .line 152
    :cond_7
    :goto_4
    check-cast p2, Ljava/lang/Throwable;

    .line 153
    .line 154
    if-eqz p2, :cond_8

    .line 155
    .line 156
    iget-object p0, p0, Lne0/n;->e:Lrx0/i;

    .line 157
    .line 158
    const/4 v2, 0x0

    .line 159
    iput-object v2, v0, Lyy0/z;->g:Lne0/n;

    .line 160
    .line 161
    iput-object v2, v0, Lyy0/z;->h:Lyy0/j;

    .line 162
    .line 163
    iput v3, v0, Lyy0/z;->e:I

    .line 164
    .line 165
    invoke-interface {p0, p1, p2, v0}, Lay0/o;->invoke(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 166
    .line 167
    .line 168
    move-result-object p0

    .line 169
    if-ne p0, v1, :cond_8

    .line 170
    .line 171
    goto :goto_6

    .line 172
    :cond_8
    :goto_5
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 173
    .line 174
    :goto_6
    return-object v1

    .line 175
    :pswitch_3
    instance-of v0, p2, Lyy0/y;

    .line 176
    .line 177
    if-eqz v0, :cond_9

    .line 178
    .line 179
    move-object v0, p2

    .line 180
    check-cast v0, Lyy0/y;

    .line 181
    .line 182
    iget v1, v0, Lyy0/y;->e:I

    .line 183
    .line 184
    const/high16 v2, -0x80000000

    .line 185
    .line 186
    and-int v3, v1, v2

    .line 187
    .line 188
    if-eqz v3, :cond_9

    .line 189
    .line 190
    sub-int/2addr v1, v2

    .line 191
    iput v1, v0, Lyy0/y;->e:I

    .line 192
    .line 193
    goto :goto_7

    .line 194
    :cond_9
    new-instance v0, Lyy0/y;

    .line 195
    .line 196
    invoke-direct {v0, p0, p2}, Lyy0/y;-><init>(Lne0/n;Lkotlin/coroutines/Continuation;)V

    .line 197
    .line 198
    .line 199
    :goto_7
    iget-object p2, v0, Lyy0/y;->d:Ljava/lang/Object;

    .line 200
    .line 201
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 202
    .line 203
    iget v2, v0, Lyy0/y;->e:I

    .line 204
    .line 205
    const/4 v3, 0x2

    .line 206
    const/4 v4, 0x1

    .line 207
    if-eqz v2, :cond_c

    .line 208
    .line 209
    if-eq v2, v4, :cond_b

    .line 210
    .line 211
    if-ne v2, v3, :cond_a

    .line 212
    .line 213
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 214
    .line 215
    .line 216
    goto :goto_9

    .line 217
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 218
    .line 219
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 220
    .line 221
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    throw p0

    .line 225
    :cond_b
    iget-object p0, v0, Lyy0/y;->i:Lzy0/r;

    .line 226
    .line 227
    iget-object p1, v0, Lyy0/y;->h:Lyy0/j;

    .line 228
    .line 229
    iget-object v2, v0, Lyy0/y;->g:Lne0/n;

    .line 230
    .line 231
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 232
    .line 233
    .line 234
    goto :goto_8

    .line 235
    :catchall_0
    move-exception p1

    .line 236
    goto :goto_b

    .line 237
    :cond_c
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 238
    .line 239
    .line 240
    new-instance p2, Lzy0/r;

    .line 241
    .line 242
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 243
    .line 244
    .line 245
    move-result-object v2

    .line 246
    invoke-direct {p2, p1, v2}, Lzy0/r;-><init>(Lyy0/j;Lpx0/g;)V

    .line 247
    .line 248
    .line 249
    :try_start_1
    iget-object v2, p0, Lne0/n;->e:Lrx0/i;

    .line 250
    .line 251
    iput-object p0, v0, Lyy0/y;->g:Lne0/n;

    .line 252
    .line 253
    iput-object p1, v0, Lyy0/y;->h:Lyy0/j;

    .line 254
    .line 255
    iput-object p2, v0, Lyy0/y;->i:Lzy0/r;

    .line 256
    .line 257
    iput v4, v0, Lyy0/y;->e:I

    .line 258
    .line 259
    invoke-interface {v2, p2, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 260
    .line 261
    .line 262
    move-result-object v2
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 263
    if-ne v2, v1, :cond_d

    .line 264
    .line 265
    goto :goto_a

    .line 266
    :cond_d
    move-object v2, p0

    .line 267
    move-object p0, p2

    .line 268
    :goto_8
    invoke-virtual {p0}, Lrx0/c;->releaseIntercepted()V

    .line 269
    .line 270
    .line 271
    iget-object p0, v2, Lne0/n;->f:Lyy0/i;

    .line 272
    .line 273
    const/4 p2, 0x0

    .line 274
    iput-object p2, v0, Lyy0/y;->g:Lne0/n;

    .line 275
    .line 276
    iput-object p2, v0, Lyy0/y;->h:Lyy0/j;

    .line 277
    .line 278
    iput-object p2, v0, Lyy0/y;->i:Lzy0/r;

    .line 279
    .line 280
    iput v3, v0, Lyy0/y;->e:I

    .line 281
    .line 282
    invoke-interface {p0, p1, v0}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 283
    .line 284
    .line 285
    move-result-object p0

    .line 286
    if-ne p0, v1, :cond_e

    .line 287
    .line 288
    goto :goto_a

    .line 289
    :cond_e
    :goto_9
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 290
    .line 291
    :goto_a
    return-object v1

    .line 292
    :catchall_1
    move-exception p1

    .line 293
    move-object p0, p2

    .line 294
    :goto_b
    invoke-virtual {p0}, Lrx0/c;->releaseIntercepted()V

    .line 295
    .line 296
    .line 297
    throw p1

    .line 298
    :pswitch_4
    new-instance v0, Lcn0/e;

    .line 299
    .line 300
    iget-object v1, p0, Lne0/n;->e:Lrx0/i;

    .line 301
    .line 302
    const/4 v2, 0x3

    .line 303
    invoke-direct {v0, p1, v1, v2}, Lcn0/e;-><init>(Lyy0/j;Lay0/k;I)V

    .line 304
    .line 305
    .line 306
    iget-object p0, p0, Lne0/n;->f:Lyy0/i;

    .line 307
    .line 308
    invoke-interface {p0, v0, p2}, Lyy0/i;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 309
    .line 310
    .line 311
    move-result-object p0

    .line 312
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 313
    .line 314
    if-ne p0, p1, :cond_f

    .line 315
    .line 316
    goto :goto_c

    .line 317
    :cond_f
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 318
    .line 319
    :goto_c
    return-object p0

    .line 320
    nop

    .line 321
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
