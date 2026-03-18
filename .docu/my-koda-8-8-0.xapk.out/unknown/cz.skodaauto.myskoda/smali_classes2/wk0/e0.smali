.class public final Lwk0/e0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lcs0/l;

.field public final i:Lij0/a;

.field public final j:Lal0/v0;


# direct methods
.method public constructor <init>(Lal0/w0;Lal0/u0;Lcs0/l;Lij0/a;Lal0/v0;)V
    .locals 3

    .line 1
    new-instance v0, Lwk0/a0;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0x7f

    .line 5
    .line 6
    invoke-direct {v0, v2, v1, v1}, Lwk0/a0;-><init>(IZZ)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p3, p0, Lwk0/e0;->h:Lcs0/l;

    .line 13
    .line 14
    iput-object p4, p0, Lwk0/e0;->i:Lij0/a;

    .line 15
    .line 16
    iput-object p5, p0, Lwk0/e0;->j:Lal0/v0;

    .line 17
    .line 18
    move-object p4, p0

    .line 19
    new-instance p0, Ltr0/e;

    .line 20
    .line 21
    move-object p3, p1

    .line 22
    const/16 p1, 0x1a

    .line 23
    .line 24
    const/4 p5, 0x0

    .line 25
    invoke-direct/range {p0 .. p5}, Ltr0/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    invoke-virtual {p4, p0}, Lql0/j;->b(Lay0/n;)V

    .line 29
    .line 30
    .line 31
    new-instance p0, Lvo0/e;

    .line 32
    .line 33
    const/16 p1, 0xc

    .line 34
    .line 35
    invoke-direct {p0, p4, p5, p1}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {p4, p0}, Lql0/j;->b(Lay0/n;)V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public static final h(Lwk0/e0;Lne0/s;Lbl0/j0;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p3, Lwk0/c0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lwk0/c0;

    .line 7
    .line 8
    iget v1, v0, Lwk0/c0;->g:I

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
    iput v1, v0, Lwk0/c0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwk0/c0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lwk0/c0;-><init>(Lwk0/e0;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lwk0/c0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwk0/c0;->g:I

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
    iget-object p0, v0, Lwk0/c0;->d:Lwk0/e0;

    .line 37
    .line 38
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    instance-of p3, p2, Lbl0/i;

    .line 54
    .line 55
    const/4 v2, 0x0

    .line 56
    if-eqz p3, :cond_3

    .line 57
    .line 58
    check-cast p2, Lbl0/i;

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    move-object p2, v2

    .line 62
    :goto_1
    if-eqz p2, :cond_4

    .line 63
    .line 64
    iget-object v2, p2, Lbl0/i;->a:Lmk0/a;

    .line 65
    .line 66
    :cond_4
    instance-of p2, p1, Lne0/e;

    .line 67
    .line 68
    if-eqz p2, :cond_6

    .line 69
    .line 70
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    check-cast p2, Lwk0/a0;

    .line 75
    .line 76
    check-cast p1, Lne0/e;

    .line 77
    .line 78
    iput-object p0, v0, Lwk0/c0;->d:Lwk0/e0;

    .line 79
    .line 80
    iput v3, v0, Lwk0/c0;->g:I

    .line 81
    .line 82
    invoke-virtual {p0, p2, p1, v2, v0}, Lwk0/e0;->j(Lwk0/a0;Lne0/e;Lmk0/a;Lrx0/c;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object p3

    .line 86
    if-ne p3, v1, :cond_5

    .line 87
    .line 88
    return-object v1

    .line 89
    :cond_5
    :goto_2
    check-cast p3, Lwk0/a0;

    .line 90
    .line 91
    goto :goto_3

    .line 92
    :cond_6
    instance-of p2, p1, Lne0/c;

    .line 93
    .line 94
    const/4 p3, 0x0

    .line 95
    if-eqz p2, :cond_7

    .line 96
    .line 97
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 98
    .line 99
    .line 100
    move-result-object p1

    .line 101
    check-cast p1, Lwk0/a0;

    .line 102
    .line 103
    const/16 p2, 0x3c

    .line 104
    .line 105
    invoke-static {p1, p3, v3, p3, p2}, Lwk0/a0;->a(Lwk0/a0;ZZZI)Lwk0/a0;

    .line 106
    .line 107
    .line 108
    move-result-object p3

    .line 109
    goto :goto_3

    .line 110
    :cond_7
    sget-object p2, Lne0/d;->a:Lne0/d;

    .line 111
    .line 112
    invoke-static {p1, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 113
    .line 114
    .line 115
    move-result p1

    .line 116
    if-eqz p1, :cond_8

    .line 117
    .line 118
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    check-cast p1, Lwk0/a0;

    .line 123
    .line 124
    const/16 p2, 0x7c

    .line 125
    .line 126
    invoke-static {p1, v3, p3, p3, p2}, Lwk0/a0;->a(Lwk0/a0;ZZZI)Lwk0/a0;

    .line 127
    .line 128
    .line 129
    move-result-object p3

    .line 130
    :goto_3
    invoke-virtual {p0, p3}, Lql0/j;->g(Lql0/h;)V

    .line 131
    .line 132
    .line 133
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 134
    .line 135
    return-object p0

    .line 136
    :cond_8
    new-instance p0, La8/r0;

    .line 137
    .line 138
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 139
    .line 140
    .line 141
    throw p0
.end method


# virtual methods
.method public final j(Lwk0/a0;Lne0/e;Lmk0/a;Lrx0/c;)Ljava/lang/Object;
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    instance-of v3, v2, Lwk0/d0;

    .line 8
    .line 9
    if-eqz v3, :cond_0

    .line 10
    .line 11
    move-object v3, v2

    .line 12
    check-cast v3, Lwk0/d0;

    .line 13
    .line 14
    iget v4, v3, Lwk0/d0;->k:I

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
    iput v4, v3, Lwk0/d0;->k:I

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    new-instance v3, Lwk0/d0;

    .line 27
    .line 28
    invoke-direct {v3, v0, v2}, Lwk0/d0;-><init>(Lwk0/e0;Lrx0/c;)V

    .line 29
    .line 30
    .line 31
    :goto_0
    iget-object v2, v3, Lwk0/d0;->i:Ljava/lang/Object;

    .line 32
    .line 33
    sget-object v4, Lqx0/a;->d:Lqx0/a;

    .line 34
    .line 35
    iget v5, v3, Lwk0/d0;->k:I

    .line 36
    .line 37
    iget-object v6, v0, Lwk0/e0;->i:Lij0/a;

    .line 38
    .line 39
    const/4 v7, 0x1

    .line 40
    if-eqz v5, :cond_2

    .line 41
    .line 42
    if-ne v5, v7, :cond_1

    .line 43
    .line 44
    iget-object v0, v3, Lwk0/d0;->h:Lij0/a;

    .line 45
    .line 46
    iget-object v1, v3, Lwk0/d0;->g:Loo0/b;

    .line 47
    .line 48
    iget-object v4, v3, Lwk0/d0;->f:Lmk0/a;

    .line 49
    .line 50
    iget-object v5, v3, Lwk0/d0;->e:Lne0/e;

    .line 51
    .line 52
    iget-object v3, v3, Lwk0/d0;->d:Lwk0/a0;

    .line 53
    .line 54
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 55
    .line 56
    .line 57
    move-object/from16 v16, v2

    .line 58
    .line 59
    move-object v2, v1

    .line 60
    move-object v1, v5

    .line 61
    move-object/from16 v5, v16

    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 65
    .line 66
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 67
    .line 68
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 69
    .line 70
    .line 71
    throw v0

    .line 72
    :cond_2
    invoke-static {v2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    iget-object v2, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 76
    .line 77
    check-cast v2, Lbl0/n;

    .line 78
    .line 79
    iget-object v2, v2, Lbl0/n;->f:Loo0/b;

    .line 80
    .line 81
    move-object/from16 v5, p1

    .line 82
    .line 83
    iput-object v5, v3, Lwk0/d0;->d:Lwk0/a0;

    .line 84
    .line 85
    iput-object v1, v3, Lwk0/d0;->e:Lne0/e;

    .line 86
    .line 87
    move-object/from16 v8, p3

    .line 88
    .line 89
    iput-object v8, v3, Lwk0/d0;->f:Lmk0/a;

    .line 90
    .line 91
    iput-object v2, v3, Lwk0/d0;->g:Loo0/b;

    .line 92
    .line 93
    iput-object v6, v3, Lwk0/d0;->h:Lij0/a;

    .line 94
    .line 95
    iput v7, v3, Lwk0/d0;->k:I

    .line 96
    .line 97
    iget-object v0, v0, Lwk0/e0;->h:Lcs0/l;

    .line 98
    .line 99
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 100
    .line 101
    .line 102
    invoke-virtual {v0, v3}, Lcs0/l;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object v0

    .line 106
    if-ne v0, v4, :cond_3

    .line 107
    .line 108
    return-object v4

    .line 109
    :cond_3
    move-object v3, v5

    .line 110
    move-object v4, v8

    .line 111
    move-object v5, v0

    .line 112
    move-object v0, v6

    .line 113
    :goto_1
    check-cast v5, Lqr0/s;

    .line 114
    .line 115
    invoke-static {v2, v0, v5}, Ljp/qd;->c(Loo0/b;Lij0/a;Lqr0/s;)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v13

    .line 119
    iget-object v0, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 120
    .line 121
    check-cast v0, Lbl0/n;

    .line 122
    .line 123
    const/4 v2, 0x0

    .line 124
    if-eqz v4, :cond_4

    .line 125
    .line 126
    iget-object v5, v4, Lmk0/a;->b:Lmk0/d;

    .line 127
    .line 128
    goto :goto_2

    .line 129
    :cond_4
    move-object v5, v2

    .line 130
    :goto_2
    if-nez v5, :cond_5

    .line 131
    .line 132
    const/4 v5, -0x1

    .line 133
    goto :goto_3

    .line 134
    :cond_5
    sget-object v8, Lwk0/b0;->a:[I

    .line 135
    .line 136
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    .line 137
    .line 138
    .line 139
    move-result v5

    .line 140
    aget v5, v8, v5

    .line 141
    .line 142
    :goto_3
    const/4 v8, 0x0

    .line 143
    if-eq v5, v7, :cond_9

    .line 144
    .line 145
    const/4 v9, 0x2

    .line 146
    if-eq v5, v9, :cond_8

    .line 147
    .line 148
    const/4 v9, 0x3

    .line 149
    if-eq v5, v9, :cond_7

    .line 150
    .line 151
    iget-object v0, v0, Lbl0/n;->b:Ljava/lang/String;

    .line 152
    .line 153
    invoke-virtual {v0}, Ljava/lang/String;->length()I

    .line 154
    .line 155
    .line 156
    move-result v5

    .line 157
    if-nez v5, :cond_6

    .line 158
    .line 159
    new-array v0, v8, [Ljava/lang/Object;

    .line 160
    .line 161
    check-cast v6, Ljj0/f;

    .line 162
    .line 163
    const v5, 0x7f120710

    .line 164
    .line 165
    .line 166
    invoke-virtual {v6, v5, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    :cond_6
    :goto_4
    move-object v11, v0

    .line 171
    goto :goto_5

    .line 172
    :cond_7
    iget-object v0, v0, Lbl0/n;->b:Ljava/lang/String;

    .line 173
    .line 174
    goto :goto_4

    .line 175
    :cond_8
    new-array v0, v8, [Ljava/lang/Object;

    .line 176
    .line 177
    check-cast v6, Ljj0/f;

    .line 178
    .line 179
    const v5, 0x7f12069d

    .line 180
    .line 181
    .line 182
    invoke-virtual {v6, v5, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    goto :goto_4

    .line 187
    :cond_9
    new-array v0, v8, [Ljava/lang/Object;

    .line 188
    .line 189
    check-cast v6, Ljj0/f;

    .line 190
    .line 191
    const v5, 0x7f120695

    .line 192
    .line 193
    .line 194
    invoke-virtual {v6, v5, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 195
    .line 196
    .line 197
    move-result-object v0

    .line 198
    goto :goto_4

    .line 199
    :goto_5
    iget-object v0, v1, Lne0/e;->a:Ljava/lang/Object;

    .line 200
    .line 201
    check-cast v0, Lbl0/n;

    .line 202
    .line 203
    iget-object v12, v0, Lbl0/n;->d:Ljava/lang/String;

    .line 204
    .line 205
    if-eqz v4, :cond_a

    .line 206
    .line 207
    iget-object v2, v4, Lmk0/a;->b:Lmk0/d;

    .line 208
    .line 209
    :cond_a
    sget-object v0, Lmk0/d;->f:Lmk0/d;

    .line 210
    .line 211
    if-ne v2, v0, :cond_b

    .line 212
    .line 213
    move v14, v7

    .line 214
    goto :goto_6

    .line 215
    :cond_b
    move v14, v8

    .line 216
    :goto_6
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 217
    .line 218
    .line 219
    const-string v0, "name"

    .line 220
    .line 221
    invoke-static {v11, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 222
    .line 223
    .line 224
    const-string v0, "address"

    .line 225
    .line 226
    invoke-static {v12, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 227
    .line 228
    .line 229
    new-instance v8, Lwk0/a0;

    .line 230
    .line 231
    const/4 v9, 0x0

    .line 232
    const/4 v10, 0x0

    .line 233
    const/4 v15, 0x0

    .line 234
    invoke-direct/range {v8 .. v15}, Lwk0/a0;-><init>(ZZLjava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)V

    .line 235
    .line 236
    .line 237
    return-object v8
.end method
