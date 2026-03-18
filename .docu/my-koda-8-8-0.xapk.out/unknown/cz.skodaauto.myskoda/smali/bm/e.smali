.class public final Lbm/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lbm/k;


# instance fields
.field public final synthetic a:I

.field public final b:Lmm/n;

.field public final c:Lez0/i;

.field public final d:Ljava/lang/Object;

.field public final e:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroid/graphics/ImageDecoder$Source;Ljava/lang/AutoCloseable;Lmm/n;Lez0/i;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Lbm/e;->a:I

    .line 6
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 7
    iput-object p1, p0, Lbm/e;->d:Ljava/lang/Object;

    .line 8
    iput-object p2, p0, Lbm/e;->e:Ljava/lang/Object;

    .line 9
    iput-object p3, p0, Lbm/e;->b:Lmm/n;

    .line 10
    iput-object p4, p0, Lbm/e;->c:Lez0/i;

    return-void
.end method

.method public constructor <init>(Lbm/q;Lmm/n;Lez0/i;Lbm/n;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lbm/e;->a:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lbm/e;->d:Ljava/lang/Object;

    .line 3
    iput-object p2, p0, Lbm/e;->b:Lmm/n;

    .line 4
    iput-object p3, p0, Lbm/e;->c:Lez0/i;

    .line 5
    iput-object p4, p0, Lbm/e;->e:Ljava/lang/Object;

    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Lbm/e;->a:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p1, Lbm/v;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    move-object v0, p1

    .line 11
    check-cast v0, Lbm/v;

    .line 12
    .line 13
    iget v1, v0, Lbm/v;->g:I

    .line 14
    .line 15
    const/high16 v2, -0x80000000

    .line 16
    .line 17
    and-int v3, v1, v2

    .line 18
    .line 19
    if-eqz v3, :cond_0

    .line 20
    .line 21
    sub-int/2addr v1, v2

    .line 22
    iput v1, v0, Lbm/v;->g:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Lbm/v;

    .line 26
    .line 27
    check-cast p1, Lrx0/c;

    .line 28
    .line 29
    invoke-direct {v0, p0, p1}, Lbm/v;-><init>(Lbm/e;Lrx0/c;)V

    .line 30
    .line 31
    .line 32
    :goto_0
    iget-object p1, v0, Lbm/v;->e:Ljava/lang/Object;

    .line 33
    .line 34
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 35
    .line 36
    iget v2, v0, Lbm/v;->g:I

    .line 37
    .line 38
    const/4 v3, 0x1

    .line 39
    if-eqz v2, :cond_2

    .line 40
    .line 41
    if-ne v2, v3, :cond_1

    .line 42
    .line 43
    iget-object v0, v0, Lbm/v;->d:Lez0/i;

    .line 44
    .line 45
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_1

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p1, p0, Lbm/e;->c:Lez0/i;

    .line 61
    .line 62
    iput-object p1, v0, Lbm/v;->d:Lez0/i;

    .line 63
    .line 64
    iput v3, v0, Lbm/v;->g:I

    .line 65
    .line 66
    invoke-virtual {p1, v0}, Lez0/h;->c(Lrx0/c;)Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object v0

    .line 70
    if-ne v0, v1, :cond_3

    .line 71
    .line 72
    goto :goto_2

    .line 73
    :cond_3
    move-object v0, p1

    .line 74
    :goto_1
    :try_start_0
    iget-object p1, p0, Lbm/e;->e:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p1, Ljava/lang/AutoCloseable;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 77
    .line 78
    :try_start_1
    new-instance v1, Lkotlin/jvm/internal/b0;

    .line 79
    .line 80
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 81
    .line 82
    .line 83
    iget-object v2, p0, Lbm/e;->d:Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v2, Landroid/graphics/ImageDecoder$Source;

    .line 86
    .line 87
    new-instance v3, Lbm/w;

    .line 88
    .line 89
    invoke-direct {v3, p0, v1}, Lbm/w;-><init>(Lbm/e;Lkotlin/jvm/internal/b0;)V

    .line 90
    .line 91
    .line 92
    invoke-static {v2, v3}, Landroid/graphics/ImageDecoder;->decodeBitmap(Landroid/graphics/ImageDecoder$Source;Landroid/graphics/ImageDecoder$OnHeaderDecodedListener;)Landroid/graphics/Bitmap;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    new-instance v2, Lbm/i;

    .line 97
    .line 98
    new-instance v3, Lyl/a;

    .line 99
    .line 100
    invoke-direct {v3, p0}, Lyl/a;-><init>(Landroid/graphics/Bitmap;)V

    .line 101
    .line 102
    .line 103
    iget-boolean p0, v1, Lkotlin/jvm/internal/b0;->d:Z

    .line 104
    .line 105
    invoke-direct {v2, v3, p0}, Lbm/i;-><init>(Lyl/j;Z)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 106
    .line 107
    .line 108
    const/4 p0, 0x0

    .line 109
    :try_start_2
    invoke-static {p1, p0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 110
    .line 111
    .line 112
    invoke-virtual {v0}, Lez0/h;->f()V

    .line 113
    .line 114
    .line 115
    move-object v1, v2

    .line 116
    :goto_2
    return-object v1

    .line 117
    :catchall_0
    move-exception p0

    .line 118
    goto :goto_3

    .line 119
    :catchall_1
    move-exception p0

    .line 120
    :try_start_3
    throw p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_2

    .line 121
    :catchall_2
    move-exception v1

    .line 122
    :try_start_4
    invoke-static {p1, p0}, Lcy0/a;->e(Ljava/lang/AutoCloseable;Ljava/lang/Throwable;)V

    .line 123
    .line 124
    .line 125
    throw v1
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 126
    :goto_3
    invoke-virtual {v0}, Lez0/h;->f()V

    .line 127
    .line 128
    .line 129
    throw p0

    .line 130
    :pswitch_0
    instance-of v0, p1, Lbm/d;

    .line 131
    .line 132
    if-eqz v0, :cond_4

    .line 133
    .line 134
    move-object v0, p1

    .line 135
    check-cast v0, Lbm/d;

    .line 136
    .line 137
    iget v1, v0, Lbm/d;->h:I

    .line 138
    .line 139
    const/high16 v2, -0x80000000

    .line 140
    .line 141
    and-int v3, v1, v2

    .line 142
    .line 143
    if-eqz v3, :cond_4

    .line 144
    .line 145
    sub-int/2addr v1, v2

    .line 146
    iput v1, v0, Lbm/d;->h:I

    .line 147
    .line 148
    goto :goto_4

    .line 149
    :cond_4
    new-instance v0, Lbm/d;

    .line 150
    .line 151
    check-cast p1, Lrx0/c;

    .line 152
    .line 153
    invoke-direct {v0, p0, p1}, Lbm/d;-><init>(Lbm/e;Lrx0/c;)V

    .line 154
    .line 155
    .line 156
    :goto_4
    iget-object p1, v0, Lbm/d;->f:Ljava/lang/Object;

    .line 157
    .line 158
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 159
    .line 160
    iget v2, v0, Lbm/d;->h:I

    .line 161
    .line 162
    const/4 v3, 0x2

    .line 163
    const/4 v4, 0x1

    .line 164
    if-eqz v2, :cond_7

    .line 165
    .line 166
    if-eq v2, v4, :cond_6

    .line 167
    .line 168
    if-ne v2, v3, :cond_5

    .line 169
    .line 170
    iget-object p0, v0, Lbm/d;->d:Lez0/e;

    .line 171
    .line 172
    :try_start_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_5
    .catchall {:try_start_5 .. :try_end_5} :catchall_3

    .line 173
    .line 174
    .line 175
    goto :goto_6

    .line 176
    :catchall_3
    move-exception p1

    .line 177
    goto :goto_9

    .line 178
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 179
    .line 180
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 181
    .line 182
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 183
    .line 184
    .line 185
    throw p0

    .line 186
    :cond_6
    iget v2, v0, Lbm/d;->e:I

    .line 187
    .line 188
    iget-object v4, v0, Lbm/d;->d:Lez0/e;

    .line 189
    .line 190
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 191
    .line 192
    .line 193
    move-object p1, v4

    .line 194
    goto :goto_5

    .line 195
    :cond_7
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 196
    .line 197
    .line 198
    iget-object p1, p0, Lbm/e;->c:Lez0/i;

    .line 199
    .line 200
    iput-object p1, v0, Lbm/d;->d:Lez0/e;

    .line 201
    .line 202
    const/4 v2, 0x0

    .line 203
    iput v2, v0, Lbm/d;->e:I

    .line 204
    .line 205
    iput v4, v0, Lbm/d;->h:I

    .line 206
    .line 207
    invoke-virtual {p1, v0}, Lez0/h;->c(Lrx0/c;)Ljava/lang/Object;

    .line 208
    .line 209
    .line 210
    move-result-object v4

    .line 211
    if-ne v4, v1, :cond_8

    .line 212
    .line 213
    goto :goto_7

    .line 214
    :cond_8
    :goto_5
    :try_start_6
    new-instance v4, La71/u;

    .line 215
    .line 216
    const/16 v5, 0x8

    .line 217
    .line 218
    invoke-direct {v4, p0, v5}, La71/u;-><init>(Ljava/lang/Object;I)V

    .line 219
    .line 220
    .line 221
    iput-object p1, v0, Lbm/d;->d:Lez0/e;

    .line 222
    .line 223
    iput v2, v0, Lbm/d;->e:I

    .line 224
    .line 225
    iput v3, v0, Lbm/d;->h:I

    .line 226
    .line 227
    sget-object p0, Lpx0/h;->d:Lpx0/h;

    .line 228
    .line 229
    new-instance v2, Ls10/a0;

    .line 230
    .line 231
    const/4 v3, 0x0

    .line 232
    const/16 v5, 0x15

    .line 233
    .line 234
    invoke-direct {v2, v4, v3, v5}, Ls10/a0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 235
    .line 236
    .line 237
    invoke-static {p0, v2, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 238
    .line 239
    .line 240
    move-result-object p0
    :try_end_6
    .catchall {:try_start_6 .. :try_end_6} :catchall_4

    .line 241
    if-ne p0, v1, :cond_9

    .line 242
    .line 243
    goto :goto_7

    .line 244
    :cond_9
    move-object v6, p1

    .line 245
    move-object p1, p0

    .line 246
    move-object p0, v6

    .line 247
    :goto_6
    :try_start_7
    move-object v1, p1

    .line 248
    check-cast v1, Lbm/i;
    :try_end_7
    .catchall {:try_start_7 .. :try_end_7} :catchall_3

    .line 249
    .line 250
    check-cast p0, Lez0/h;

    .line 251
    .line 252
    invoke-virtual {p0}, Lez0/h;->f()V

    .line 253
    .line 254
    .line 255
    :goto_7
    return-object v1

    .line 256
    :goto_8
    move-object v6, p1

    .line 257
    move-object p1, p0

    .line 258
    move-object p0, v6

    .line 259
    goto :goto_9

    .line 260
    :catchall_4
    move-exception p0

    .line 261
    goto :goto_8

    .line 262
    :goto_9
    check-cast p0, Lez0/h;

    .line 263
    .line 264
    invoke-virtual {p0}, Lez0/h;->f()V

    .line 265
    .line 266
    .line 267
    throw p1

    .line 268
    nop

    .line 269
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
