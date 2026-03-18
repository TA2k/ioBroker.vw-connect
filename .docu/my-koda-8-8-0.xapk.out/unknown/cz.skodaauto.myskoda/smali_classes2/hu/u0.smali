.class public final Lhu/u0;
.super Lrx0/i;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# instance fields
.field public final synthetic d:I

.field public synthetic e:Ljava/lang/Object;

.field public final synthetic f:Lhu/w0;


# direct methods
.method public synthetic constructor <init>(Lhu/w0;Lkotlin/coroutines/Continuation;I)V
    .locals 0

    .line 1
    iput p3, p0, Lhu/u0;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lhu/u0;->f:Lhu/w0;

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
    .locals 2

    .line 1
    iget v0, p0, Lhu/u0;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance v0, Lhu/u0;

    .line 7
    .line 8
    iget-object p0, p0, Lhu/u0;->f:Lhu/w0;

    .line 9
    .line 10
    const/4 v1, 0x1

    .line 11
    invoke-direct {v0, p0, p2, v1}, Lhu/u0;-><init>(Lhu/w0;Lkotlin/coroutines/Continuation;I)V

    .line 12
    .line 13
    .line 14
    iput-object p1, v0, Lhu/u0;->e:Ljava/lang/Object;

    .line 15
    .line 16
    return-object v0

    .line 17
    :pswitch_0
    new-instance v0, Lhu/u0;

    .line 18
    .line 19
    iget-object p0, p0, Lhu/u0;->f:Lhu/w0;

    .line 20
    .line 21
    const/4 v1, 0x0

    .line 22
    invoke-direct {v0, p0, p2, v1}, Lhu/u0;-><init>(Lhu/w0;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    iput-object p1, v0, Lhu/u0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    return-object v0

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lhu/u0;->d:I

    .line 2
    .line 3
    check-cast p1, Lhu/e0;

    .line 4
    .line 5
    check-cast p2, Lkotlin/coroutines/Continuation;

    .line 6
    .line 7
    packed-switch v0, :pswitch_data_0

    .line 8
    .line 9
    .line 10
    invoke-virtual {p0, p1, p2}, Lhu/u0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lhu/u0;

    .line 15
    .line 16
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 17
    .line 18
    invoke-virtual {p0, p1}, Lhu/u0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    return-object p0

    .line 23
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lhu/u0;->create(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Lkotlin/coroutines/Continuation;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    check-cast p0, Lhu/u0;

    .line 28
    .line 29
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lhu/u0;->invokeSuspend(Ljava/lang/Object;)Ljava/lang/Object;

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
    iget v0, p0, Lhu/u0;->d:I

    .line 2
    .line 3
    iget-object v1, p0, Lhu/u0;->f:Lhu/w0;

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    packed-switch v0, :pswitch_data_0

    .line 7
    .line 8
    .line 9
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 10
    .line 11
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 12
    .line 13
    .line 14
    iget-object p0, p0, Lhu/u0;->e:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast p0, Lhu/e0;

    .line 17
    .line 18
    invoke-virtual {v1, p0}, Lhu/w0;->d(Lhu/e0;)Z

    .line 19
    .line 20
    .line 21
    move-result p1

    .line 22
    iget-object v0, v1, Lhu/w0;->f:Lhu/a0;

    .line 23
    .line 24
    iget-object v3, p0, Lhu/e0;->c:Ljava/util/Map;

    .line 25
    .line 26
    const-string v4, "FirebaseSessions"

    .line 27
    .line 28
    const/4 v5, 0x1

    .line 29
    if-eqz v3, :cond_9

    .line 30
    .line 31
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    iget-boolean v6, v0, Lhu/a0;->f:Z

    .line 35
    .line 36
    const/4 v7, 0x0

    .line 37
    if-eqz v6, :cond_0

    .line 38
    .line 39
    goto/16 :goto_3

    .line 40
    .line 41
    :cond_0
    iget-object v6, v0, Lhu/a0;->a:Landroid/content/Context;

    .line 42
    .line 43
    invoke-static {v6}, Lhu/r;->a(Landroid/content/Context;)Ljava/util/ArrayList;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    new-instance v8, Ljava/util/ArrayList;

    .line 48
    .line 49
    invoke-direct {v8}, Ljava/util/ArrayList;-><init>()V

    .line 50
    .line 51
    .line 52
    invoke-virtual {v6}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 53
    .line 54
    .line 55
    move-result-object v6

    .line 56
    :cond_1
    :goto_0
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 57
    .line 58
    .line 59
    move-result v9

    .line 60
    if-eqz v9, :cond_3

    .line 61
    .line 62
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v9

    .line 66
    check-cast v9, Lhu/b0;

    .line 67
    .line 68
    iget-object v10, v9, Lhu/b0;->a:Ljava/lang/String;

    .line 69
    .line 70
    invoke-interface {v3, v10}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object v10

    .line 74
    check-cast v10, Lhu/y;

    .line 75
    .line 76
    if-eqz v10, :cond_2

    .line 77
    .line 78
    new-instance v11, Llx0/l;

    .line 79
    .line 80
    invoke-direct {v11, v9, v10}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 81
    .line 82
    .line 83
    goto :goto_1

    .line 84
    :cond_2
    move-object v11, v2

    .line 85
    :goto_1
    if-eqz v11, :cond_1

    .line 86
    .line 87
    invoke-virtual {v8, v11}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    goto :goto_0

    .line 91
    :cond_3
    invoke-virtual {v8}, Ljava/util/ArrayList;->isEmpty()Z

    .line 92
    .line 93
    .line 94
    move-result v6

    .line 95
    if-eqz v6, :cond_5

    .line 96
    .line 97
    :cond_4
    move v7, v5

    .line 98
    goto :goto_3

    .line 99
    :cond_5
    invoke-virtual {v8}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    :cond_6
    :goto_2
    invoke-interface {v6}, Ljava/util/Iterator;->hasNext()Z

    .line 104
    .line 105
    .line 106
    move-result v8

    .line 107
    if-eqz v8, :cond_4

    .line 108
    .line 109
    invoke-interface {v6}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object v8

    .line 113
    check-cast v8, Llx0/l;

    .line 114
    .line 115
    iget-object v9, v8, Llx0/l;->d:Ljava/lang/Object;

    .line 116
    .line 117
    check-cast v9, Lhu/b0;

    .line 118
    .line 119
    iget-object v8, v8, Llx0/l;->e:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v8, Lhu/y;

    .line 122
    .line 123
    invoke-virtual {v0}, Lhu/a0;->a()Ljava/lang/String;

    .line 124
    .line 125
    .line 126
    move-result-object v10

    .line 127
    iget-object v11, v9, Lhu/b0;->a:Ljava/lang/String;

    .line 128
    .line 129
    iget v9, v9, Lhu/b0;->b:I

    .line 130
    .line 131
    invoke-static {v10, v11}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 132
    .line 133
    .line 134
    move-result v10

    .line 135
    if-eqz v10, :cond_7

    .line 136
    .line 137
    iget v10, v8, Lhu/y;->a:I

    .line 138
    .line 139
    if-ne v9, v10, :cond_6

    .line 140
    .line 141
    iget-object v9, v0, Lhu/a0;->d:Llx0/q;

    .line 142
    .line 143
    invoke-virtual {v9}, Llx0/q;->getValue()Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v9

    .line 147
    check-cast v9, Ljava/lang/String;

    .line 148
    .line 149
    iget-object v8, v8, Lhu/y;->b:Ljava/lang/String;

    .line 150
    .line 151
    invoke-static {v9, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 152
    .line 153
    .line 154
    move-result v8

    .line 155
    if-nez v8, :cond_8

    .line 156
    .line 157
    goto :goto_2

    .line 158
    :cond_7
    iget v8, v8, Lhu/y;->a:I

    .line 159
    .line 160
    if-eq v9, v8, :cond_8

    .line 161
    .line 162
    goto :goto_2

    .line 163
    :cond_8
    :goto_3
    if-eqz v7, :cond_a

    .line 164
    .line 165
    const-string v6, "Cold app start detected"

    .line 166
    .line 167
    invoke-static {v4, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 168
    .line 169
    .line 170
    goto :goto_4

    .line 171
    :cond_9
    const-string v6, "No process data map"

    .line 172
    .line 173
    invoke-static {v4, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 174
    .line 175
    .line 176
    move v7, v5

    .line 177
    :cond_a
    :goto_4
    invoke-virtual {v1, p0}, Lhu/w0;->c(Lhu/e0;)Z

    .line 178
    .line 179
    .line 180
    move-result v4

    .line 181
    if-eqz v7, :cond_b

    .line 182
    .line 183
    sget-object v3, Lmx0/t;->d:Lmx0/t;

    .line 184
    .line 185
    invoke-virtual {v0, v3}, Lhu/a0;->b(Ljava/util/Map;)Ljava/util/Map;

    .line 186
    .line 187
    .line 188
    move-result-object v3

    .line 189
    goto :goto_5

    .line 190
    :cond_b
    if-eqz v4, :cond_c

    .line 191
    .line 192
    invoke-virtual {v0, v3}, Lhu/a0;->b(Ljava/util/Map;)Ljava/util/Map;

    .line 193
    .line 194
    .line 195
    move-result-object v3

    .line 196
    :cond_c
    :goto_5
    if-eqz v7, :cond_d

    .line 197
    .line 198
    move-object v6, v2

    .line 199
    goto :goto_6

    .line 200
    :cond_d
    iget-object v6, p0, Lhu/e0;->a:Lhu/j0;

    .line 201
    .line 202
    :goto_6
    const/4 v8, 0x3

    .line 203
    if-nez p1, :cond_f

    .line 204
    .line 205
    if-eqz v7, :cond_e

    .line 206
    .line 207
    goto :goto_7

    .line 208
    :cond_e
    if-eqz v4, :cond_10

    .line 209
    .line 210
    invoke-virtual {v0, v3}, Lhu/a0;->b(Ljava/util/Map;)Ljava/util/Map;

    .line 211
    .line 212
    .line 213
    move-result-object p1

    .line 214
    invoke-static {p0, v2, v2, p1, v8}, Lhu/e0;->a(Lhu/e0;Lhu/j0;Lhu/z0;Ljava/util/Map;I)Lhu/e0;

    .line 215
    .line 216
    .line 217
    move-result-object p0

    .line 218
    goto :goto_8

    .line 219
    :cond_f
    :goto_7
    iget-object p0, v1, Lhu/w0;->b:Lhu/p0;

    .line 220
    .line 221
    invoke-virtual {p0, v6}, Lhu/p0;->a(Lhu/j0;)Lhu/j0;

    .line 222
    .line 223
    .line 224
    move-result-object p0

    .line 225
    iget-object p1, v1, Lhu/w0;->c:Lhu/m0;

    .line 226
    .line 227
    check-cast p1, Lhu/o0;

    .line 228
    .line 229
    iget-object v1, p1, Lhu/o0;->e:Lpx0/g;

    .line 230
    .line 231
    invoke-static {v1}, Lvy0/e0;->c(Lpx0/g;)Lpw0/a;

    .line 232
    .line 233
    .line 234
    move-result-object v1

    .line 235
    new-instance v4, Lg1/y0;

    .line 236
    .line 237
    invoke-direct {v4, p1, p0, v2}, Lg1/y0;-><init>(Lhu/o0;Lhu/j0;Lkotlin/coroutines/Continuation;)V

    .line 238
    .line 239
    .line 240
    invoke-static {v1, v2, v2, v4, v8}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 241
    .line 242
    .line 243
    iput-boolean v5, v0, Lhu/a0;->f:Z

    .line 244
    .line 245
    new-instance p1, Lhu/e0;

    .line 246
    .line 247
    invoke-direct {p1, p0, v2, v3}, Lhu/e0;-><init>(Lhu/j0;Lhu/z0;Ljava/util/Map;)V

    .line 248
    .line 249
    .line 250
    move-object p0, p1

    .line 251
    :cond_10
    :goto_8
    return-object p0

    .line 252
    :pswitch_0
    sget-object v0, Lqx0/a;->d:Lqx0/a;

    .line 253
    .line 254
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 255
    .line 256
    .line 257
    iget-object p0, p0, Lhu/u0;->e:Ljava/lang/Object;

    .line 258
    .line 259
    check-cast p0, Lhu/e0;

    .line 260
    .line 261
    iget-object p1, v1, Lhu/w0;->d:Lhu/a1;

    .line 262
    .line 263
    invoke-virtual {p1}, Lhu/a1;->a()Lhu/z0;

    .line 264
    .line 265
    .line 266
    move-result-object p1

    .line 267
    const/4 v0, 0x5

    .line 268
    invoke-static {p0, v2, p1, v2, v0}, Lhu/e0;->a(Lhu/e0;Lhu/j0;Lhu/z0;Ljava/util/Map;I)Lhu/e0;

    .line 269
    .line 270
    .line 271
    move-result-object p0

    .line 272
    return-object p0

    .line 273
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
