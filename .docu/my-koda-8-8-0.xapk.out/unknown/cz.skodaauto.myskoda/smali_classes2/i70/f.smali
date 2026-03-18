.class public final Li70/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lyy0/j;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lyy0/j;

.field public final synthetic f:Li70/n;


# direct methods
.method public synthetic constructor <init>(Lyy0/j;Li70/n;I)V
    .locals 0

    .line 1
    iput p3, p0, Li70/f;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li70/f;->e:Lyy0/j;

    .line 4
    .line 5
    iput-object p2, p0, Li70/f;->f:Li70/n;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    iget v0, p0, Li70/f;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    instance-of v0, p2, Li70/j;

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    move-object v0, p2

    .line 11
    check-cast v0, Li70/j;

    .line 12
    .line 13
    iget v1, v0, Li70/j;->e:I

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
    iput v1, v0, Li70/j;->e:I

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    new-instance v0, Li70/j;

    .line 26
    .line 27
    invoke-direct {v0, p0, p2}, Li70/j;-><init>(Li70/f;Lkotlin/coroutines/Continuation;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    iget-object p2, v0, Li70/j;->d:Ljava/lang/Object;

    .line 31
    .line 32
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 33
    .line 34
    iget v2, v0, Li70/j;->e:I

    .line 35
    .line 36
    const/4 v3, 0x1

    .line 37
    if-eqz v2, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_2

    .line 45
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 46
    .line 47
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 48
    .line 49
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 50
    .line 51
    .line 52
    throw p0

    .line 53
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    check-cast p1, Ljava/lang/String;

    .line 57
    .line 58
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 59
    .line 60
    .line 61
    move-result p2

    .line 62
    const/4 v2, 0x0

    .line 63
    if-lez p2, :cond_3

    .line 64
    .line 65
    :try_start_0
    invoke-static {p1}, Ll70/w;->valueOf(Ljava/lang/String;)Ll70/w;

    .line 66
    .line 67
    .line 68
    move-result-object v2
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 69
    goto :goto_1

    .line 70
    :catch_0
    move-exception p2

    .line 71
    new-instance v4, Li70/g;

    .line 72
    .line 73
    const/4 v5, 0x2

    .line 74
    invoke-direct {v4, p1, p2, v5}, Li70/g;-><init>(Ljava/lang/String;Ljava/lang/IllegalArgumentException;I)V

    .line 75
    .line 76
    .line 77
    iget-object p1, p0, Li70/f;->f:Li70/n;

    .line 78
    .line 79
    invoke-static {v2, p1, v4}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 80
    .line 81
    .line 82
    :cond_3
    :goto_1
    iput v3, v0, Li70/j;->e:I

    .line 83
    .line 84
    iget-object p0, p0, Li70/f;->e:Lyy0/j;

    .line 85
    .line 86
    invoke-interface {p0, v2, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 87
    .line 88
    .line 89
    move-result-object p0

    .line 90
    if-ne p0, v1, :cond_4

    .line 91
    .line 92
    goto :goto_3

    .line 93
    :cond_4
    :goto_2
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 94
    .line 95
    :goto_3
    return-object v1

    .line 96
    :pswitch_0
    instance-of v0, p2, Li70/h;

    .line 97
    .line 98
    if-eqz v0, :cond_5

    .line 99
    .line 100
    move-object v0, p2

    .line 101
    check-cast v0, Li70/h;

    .line 102
    .line 103
    iget v1, v0, Li70/h;->e:I

    .line 104
    .line 105
    const/high16 v2, -0x80000000

    .line 106
    .line 107
    and-int v3, v1, v2

    .line 108
    .line 109
    if-eqz v3, :cond_5

    .line 110
    .line 111
    sub-int/2addr v1, v2

    .line 112
    iput v1, v0, Li70/h;->e:I

    .line 113
    .line 114
    goto :goto_4

    .line 115
    :cond_5
    new-instance v0, Li70/h;

    .line 116
    .line 117
    invoke-direct {v0, p0, p2}, Li70/h;-><init>(Li70/f;Lkotlin/coroutines/Continuation;)V

    .line 118
    .line 119
    .line 120
    :goto_4
    iget-object p2, v0, Li70/h;->d:Ljava/lang/Object;

    .line 121
    .line 122
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 123
    .line 124
    iget v2, v0, Li70/h;->e:I

    .line 125
    .line 126
    const/4 v3, 0x1

    .line 127
    if-eqz v2, :cond_7

    .line 128
    .line 129
    if-ne v2, v3, :cond_6

    .line 130
    .line 131
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 132
    .line 133
    .line 134
    goto :goto_6

    .line 135
    :cond_6
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 136
    .line 137
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 138
    .line 139
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    throw p0

    .line 143
    :cond_7
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 144
    .line 145
    .line 146
    check-cast p1, Ljava/lang/String;

    .line 147
    .line 148
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 149
    .line 150
    .line 151
    move-result p2

    .line 152
    const/4 v2, 0x0

    .line 153
    if-lez p2, :cond_8

    .line 154
    .line 155
    :try_start_1
    invoke-static {p1}, Ll70/q;->valueOf(Ljava/lang/String;)Ll70/q;

    .line 156
    .line 157
    .line 158
    move-result-object v2
    :try_end_1
    .catch Ljava/lang/IllegalArgumentException; {:try_start_1 .. :try_end_1} :catch_1

    .line 159
    goto :goto_5

    .line 160
    :catch_1
    move-exception p2

    .line 161
    new-instance v4, Li70/g;

    .line 162
    .line 163
    const/4 v5, 0x1

    .line 164
    invoke-direct {v4, p1, p2, v5}, Li70/g;-><init>(Ljava/lang/String;Ljava/lang/IllegalArgumentException;I)V

    .line 165
    .line 166
    .line 167
    iget-object p1, p0, Li70/f;->f:Li70/n;

    .line 168
    .line 169
    invoke-static {v2, p1, v4}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 170
    .line 171
    .line 172
    :cond_8
    :goto_5
    iput v3, v0, Li70/h;->e:I

    .line 173
    .line 174
    iget-object p0, p0, Li70/f;->e:Lyy0/j;

    .line 175
    .line 176
    invoke-interface {p0, v2, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 177
    .line 178
    .line 179
    move-result-object p0

    .line 180
    if-ne p0, v1, :cond_9

    .line 181
    .line 182
    goto :goto_7

    .line 183
    :cond_9
    :goto_6
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 184
    .line 185
    :goto_7
    return-object v1

    .line 186
    :pswitch_1
    instance-of v0, p2, Li70/e;

    .line 187
    .line 188
    if-eqz v0, :cond_a

    .line 189
    .line 190
    move-object v0, p2

    .line 191
    check-cast v0, Li70/e;

    .line 192
    .line 193
    iget v1, v0, Li70/e;->e:I

    .line 194
    .line 195
    const/high16 v2, -0x80000000

    .line 196
    .line 197
    and-int v3, v1, v2

    .line 198
    .line 199
    if-eqz v3, :cond_a

    .line 200
    .line 201
    sub-int/2addr v1, v2

    .line 202
    iput v1, v0, Li70/e;->e:I

    .line 203
    .line 204
    goto :goto_8

    .line 205
    :cond_a
    new-instance v0, Li70/e;

    .line 206
    .line 207
    invoke-direct {v0, p0, p2}, Li70/e;-><init>(Li70/f;Lkotlin/coroutines/Continuation;)V

    .line 208
    .line 209
    .line 210
    :goto_8
    iget-object p2, v0, Li70/e;->d:Ljava/lang/Object;

    .line 211
    .line 212
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 213
    .line 214
    iget v2, v0, Li70/e;->e:I

    .line 215
    .line 216
    const/4 v3, 0x1

    .line 217
    if-eqz v2, :cond_c

    .line 218
    .line 219
    if-ne v2, v3, :cond_b

    .line 220
    .line 221
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 222
    .line 223
    .line 224
    goto :goto_a

    .line 225
    :cond_b
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 226
    .line 227
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 228
    .line 229
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 230
    .line 231
    .line 232
    throw p0

    .line 233
    :cond_c
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 234
    .line 235
    .line 236
    check-cast p1, Ljava/util/Set;

    .line 237
    .line 238
    new-instance p2, Ljava/util/ArrayList;

    .line 239
    .line 240
    invoke-direct {p2}, Ljava/util/ArrayList;-><init>()V

    .line 241
    .line 242
    .line 243
    check-cast p1, Ljava/lang/Iterable;

    .line 244
    .line 245
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 246
    .line 247
    .line 248
    move-result-object p1

    .line 249
    :goto_9
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 250
    .line 251
    .line 252
    move-result v2

    .line 253
    if-eqz v2, :cond_d

    .line 254
    .line 255
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 256
    .line 257
    .line 258
    move-result-object v2

    .line 259
    check-cast v2, Ljava/lang/String;

    .line 260
    .line 261
    :try_start_2
    invoke-static {v2}, Ll70/q;->valueOf(Ljava/lang/String;)Ll70/q;

    .line 262
    .line 263
    .line 264
    move-result-object v4

    .line 265
    invoke-virtual {p2, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z
    :try_end_2
    .catch Ljava/lang/IllegalArgumentException; {:try_start_2 .. :try_end_2} :catch_2

    .line 266
    .line 267
    .line 268
    goto :goto_9

    .line 269
    :catch_2
    move-exception v4

    .line 270
    new-instance v5, Li70/g;

    .line 271
    .line 272
    const/4 v6, 0x0

    .line 273
    invoke-direct {v5, v2, v4, v6}, Li70/g;-><init>(Ljava/lang/String;Ljava/lang/IllegalArgumentException;I)V

    .line 274
    .line 275
    .line 276
    const/4 v2, 0x0

    .line 277
    iget-object v4, p0, Li70/f;->f:Li70/n;

    .line 278
    .line 279
    invoke-static {v2, v4, v5}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 280
    .line 281
    .line 282
    goto :goto_9

    .line 283
    :cond_d
    iput v3, v0, Li70/e;->e:I

    .line 284
    .line 285
    iget-object p0, p0, Li70/f;->e:Lyy0/j;

    .line 286
    .line 287
    invoke-interface {p0, p2, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 288
    .line 289
    .line 290
    move-result-object p0

    .line 291
    if-ne p0, v1, :cond_e

    .line 292
    .line 293
    goto :goto_b

    .line 294
    :cond_e
    :goto_a
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 295
    .line 296
    :goto_b
    return-object v1

    .line 297
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method
