.class public final Lhv0/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lhv0/y;

.field public final b:Lhv0/h0;

.field public final c:Lwj0/f0;

.field public final d:Lnn0/t;

.field public final e:Lhv0/l;


# direct methods
.method public constructor <init>(Lhv0/y;Lhv0/h0;Lwj0/f0;Lnn0/t;Lhv0/l;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhv0/w;->a:Lhv0/y;

    .line 5
    .line 6
    iput-object p2, p0, Lhv0/w;->b:Lhv0/h0;

    .line 7
    .line 8
    iput-object p3, p0, Lhv0/w;->c:Lwj0/f0;

    .line 9
    .line 10
    iput-object p4, p0, Lhv0/w;->d:Lnn0/t;

    .line 11
    .line 12
    iput-object p5, p0, Lhv0/w;->e:Lhv0/l;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Liv0/f;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lhv0/w;->b(Liv0/f;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Liv0/f;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    move-object/from16 v0, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    instance-of v3, v2, Lhv0/v;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lhv0/v;

    .line 13
    .line 14
    iget v4, v3, Lhv0/v;->g:I

    .line 15
    .line 16
    const/high16 v5, -0x80000000

    .line 17
    .line 18
    and-int v6, v4, v5

    .line 19
    .line 20
    if-eqz v6, :cond_0

    .line 21
    .line 22
    sub-int/2addr v4, v5

    .line 23
    iput v4, v3, Lhv0/v;->g:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lhv0/v;

    .line 27
    .line 28
    invoke-direct {v3, v1, v2}, Lhv0/v;-><init>(Lhv0/w;Lkotlin/coroutines/Continuation;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lhv0/v;->e:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lhv0/v;->g:I

    .line 36
    .line 37
    const/4 v6, 0x3

    .line 38
    const/4 v7, 0x2

    .line 39
    sget-object v8, Llx0/b0;->a:Llx0/b0;

    .line 40
    .line 41
    const/4 v9, 0x1

    .line 42
    const/4 v10, 0x0

    .line 43
    if-eqz v5, :cond_5

    .line 44
    .line 45
    if-eq v5, v9, :cond_4

    .line 46
    .line 47
    if-eq v5, v7, :cond_2

    .line 48
    .line 49
    if-ne v5, v6, :cond_1

    .line 50
    .line 51
    iget-object v3, v3, Lhv0/v;->d:Liv0/f;

    .line 52
    .line 53
    :try_start_0
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 54
    .line 55
    .line 56
    goto/16 :goto_5

    .line 57
    .line 58
    :catchall_0
    move-exception v0

    .line 59
    goto/16 :goto_6

    .line 60
    .line 61
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 64
    .line 65
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw v0

    .line 69
    :cond_2
    iget-object v0, v3, Lhv0/v;->d:Liv0/f;

    .line 70
    .line 71
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 72
    .line 73
    .line 74
    :cond_3
    move-object v5, v0

    .line 75
    goto :goto_2

    .line 76
    :cond_4
    iget-object v0, v3, Lhv0/v;->d:Liv0/f;

    .line 77
    .line 78
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_1

    .line 82
    :cond_5
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    iput-object v0, v3, Lhv0/v;->d:Liv0/f;

    .line 86
    .line 87
    iput v9, v3, Lhv0/v;->g:I

    .line 88
    .line 89
    iget-object v2, v1, Lhv0/w;->b:Lhv0/h0;

    .line 90
    .line 91
    invoke-virtual {v2, v0, v3}, Lhv0/h0;->b(Liv0/f;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v2

    .line 95
    if-ne v2, v4, :cond_6

    .line 96
    .line 97
    goto :goto_4

    .line 98
    :cond_6
    :goto_1
    instance-of v2, v0, Liv0/h;

    .line 99
    .line 100
    if-eqz v2, :cond_b

    .line 101
    .line 102
    iget-object v2, v1, Lhv0/w;->d:Lnn0/t;

    .line 103
    .line 104
    invoke-virtual {v2}, Lnn0/t;->invoke()Ljava/lang/Object;

    .line 105
    .line 106
    .line 107
    move-result-object v2

    .line 108
    check-cast v2, Lyy0/i;

    .line 109
    .line 110
    invoke-static {v2}, Lbb/j0;->l(Lyy0/i;)Lal0/j0;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    iput-object v0, v3, Lhv0/v;->d:Liv0/f;

    .line 115
    .line 116
    iput v7, v3, Lhv0/v;->g:I

    .line 117
    .line 118
    invoke-static {v2, v3}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v2

    .line 122
    if-ne v2, v4, :cond_3

    .line 123
    .line 124
    goto :goto_4

    .line 125
    :goto_2
    instance-of v0, v2, Lne0/e;

    .line 126
    .line 127
    if-eqz v0, :cond_7

    .line 128
    .line 129
    check-cast v2, Lne0/e;

    .line 130
    .line 131
    goto :goto_3

    .line 132
    :cond_7
    move-object v2, v10

    .line 133
    :goto_3
    if-eqz v2, :cond_a

    .line 134
    .line 135
    iget-object v0, v2, Lne0/e;->a:Ljava/lang/Object;

    .line 136
    .line 137
    check-cast v0, Lon0/t;

    .line 138
    .line 139
    if-eqz v0, :cond_a

    .line 140
    .line 141
    :try_start_1
    iget-object v2, v1, Lhv0/w;->c:Lwj0/f0;

    .line 142
    .line 143
    new-instance v7, Lxj0/l;

    .line 144
    .line 145
    iget-object v11, v0, Lon0/t;->b:Ljava/lang/String;

    .line 146
    .line 147
    iget-object v0, v0, Lon0/t;->e:Lxj0/f;

    .line 148
    .line 149
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 150
    .line 151
    .line 152
    invoke-direct {v7, v11, v0}, Lxj0/l;-><init>(Ljava/lang/String;Lxj0/f;)V

    .line 153
    .line 154
    .line 155
    iput-object v5, v3, Lhv0/v;->d:Liv0/f;

    .line 156
    .line 157
    iput v6, v3, Lhv0/v;->g:I

    .line 158
    .line 159
    invoke-virtual {v2, v7}, Lwj0/f0;->c(Lxj0/r;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 160
    .line 161
    .line 162
    if-ne v8, v4, :cond_8

    .line 163
    .line 164
    :goto_4
    return-object v4

    .line 165
    :cond_8
    move-object v3, v5

    .line 166
    :goto_5
    move-object v0, v8

    .line 167
    goto :goto_7

    .line 168
    :catchall_1
    move-exception v0

    .line 169
    move-object v3, v5

    .line 170
    :goto_6
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 171
    .line 172
    .line 173
    move-result-object v0

    .line 174
    :goto_7
    invoke-static {v0}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 175
    .line 176
    .line 177
    move-result-object v0

    .line 178
    if-eqz v0, :cond_9

    .line 179
    .line 180
    new-instance v2, Lbp0/e;

    .line 181
    .line 182
    const/4 v4, 0x2

    .line 183
    invoke-direct {v2, v0, v4}, Lbp0/e;-><init>(Ljava/lang/Throwable;I)V

    .line 184
    .line 185
    .line 186
    invoke-static {v10, v1, v2}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 187
    .line 188
    .line 189
    :cond_9
    move-object v0, v3

    .line 190
    goto :goto_8

    .line 191
    :cond_a
    move-object v0, v5

    .line 192
    :cond_b
    :goto_8
    iget-object v2, v1, Lhv0/w;->a:Lhv0/y;

    .line 193
    .line 194
    invoke-virtual {v2, v9}, Lhv0/y;->a(Z)V

    .line 195
    .line 196
    .line 197
    iget-object v1, v1, Lhv0/w;->e:Lhv0/l;

    .line 198
    .line 199
    check-cast v1, Liy/b;

    .line 200
    .line 201
    const-string v2, "feature"

    .line 202
    .line 203
    invoke-static {v0, v2}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 204
    .line 205
    .line 206
    sget-object v12, Lly/b;->e:Lly/b;

    .line 207
    .line 208
    sget-object v2, Liv0/a;->a:Liv0/a;

    .line 209
    .line 210
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 211
    .line 212
    .line 213
    move-result v2

    .line 214
    if-eqz v2, :cond_c

    .line 215
    .line 216
    sget-object v10, Lly/b;->c2:Lly/b;

    .line 217
    .line 218
    :goto_9
    move-object v14, v10

    .line 219
    goto :goto_a

    .line 220
    :cond_c
    sget-object v2, Liv0/c;->a:Liv0/c;

    .line 221
    .line 222
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 223
    .line 224
    .line 225
    move-result v2

    .line 226
    if-eqz v2, :cond_d

    .line 227
    .line 228
    sget-object v10, Lly/b;->d2:Lly/b;

    .line 229
    .line 230
    goto :goto_9

    .line 231
    :cond_d
    sget-object v2, Liv0/h;->a:Liv0/h;

    .line 232
    .line 233
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 234
    .line 235
    .line 236
    move-result v2

    .line 237
    if-eqz v2, :cond_e

    .line 238
    .line 239
    sget-object v10, Lly/b;->e2:Lly/b;

    .line 240
    .line 241
    goto :goto_9

    .line 242
    :cond_e
    sget-object v2, Liv0/n;->a:Liv0/n;

    .line 243
    .line 244
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 245
    .line 246
    .line 247
    move-result v2

    .line 248
    if-eqz v2, :cond_f

    .line 249
    .line 250
    sget-object v10, Lly/b;->b2:Lly/b;

    .line 251
    .line 252
    goto :goto_9

    .line 253
    :cond_f
    new-instance v2, Ljv0/d;

    .line 254
    .line 255
    const/4 v3, 0x1

    .line 256
    invoke-direct {v2, v0, v3}, Ljv0/d;-><init>(Liv0/f;I)V

    .line 257
    .line 258
    .line 259
    invoke-static {v10, v0, v2}, Llp/nd;->g(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 260
    .line 261
    .line 262
    goto :goto_9

    .line 263
    :goto_a
    new-instance v11, Lul0/c;

    .line 264
    .line 265
    const/4 v15, 0x0

    .line 266
    const/16 v16, 0x10

    .line 267
    .line 268
    const/4 v13, 0x1

    .line 269
    invoke-direct/range {v11 .. v16}, Lul0/c;-><init>(Lul0/f;ZLul0/f;Ljava/util/List;I)V

    .line 270
    .line 271
    .line 272
    invoke-virtual {v1, v11}, Liy/b;->b(Lul0/e;)V

    .line 273
    .line 274
    .line 275
    return-object v8
.end method
