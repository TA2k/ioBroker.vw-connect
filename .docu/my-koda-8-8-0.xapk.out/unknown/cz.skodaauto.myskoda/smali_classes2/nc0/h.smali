.class public final Lnc0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Luc0/a;
.implements Lhs0/a;
.implements Lli0/a;
.implements Ld01/c;


# instance fields
.field public final b:Lkc0/t0;

.field public final c:Lkc0/u0;


# direct methods
.method public constructor <init>(Lkc0/t0;Lkc0/u0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnc0/h;->b:Lkc0/t0;

    .line 5
    .line 6
    iput-object p2, p0, Lnc0/h;->c:Lkc0/u0;

    .line 7
    .line 8
    return-void
.end method

.method public static final b(Lnc0/h;Ld01/t0;Lrx0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p2, Ldm0/c;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Ldm0/c;

    .line 7
    .line 8
    iget v1, v0, Ldm0/c;->k:I

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
    iput v1, v0, Ldm0/c;->k:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Ldm0/c;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Ldm0/c;-><init>(Lnc0/h;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Ldm0/c;->i:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Ldm0/c;->k:I

    .line 30
    .line 31
    const/4 v3, 0x0

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v5, :cond_2

    .line 37
    .line 38
    if-ne v2, v4, :cond_1

    .line 39
    .line 40
    iget p1, v0, Ldm0/c;->f:I

    .line 41
    .line 42
    iget v2, v0, Ldm0/c;->e:I

    .line 43
    .line 44
    iget-object v6, v0, Ldm0/c;->d:Ld01/t0;

    .line 45
    .line 46
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    move v7, v2

    .line 50
    goto/16 :goto_7

    .line 51
    .line 52
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 53
    .line 54
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 55
    .line 56
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 57
    .line 58
    .line 59
    throw p0

    .line 60
    :cond_2
    iget p1, v0, Ldm0/c;->h:I

    .line 61
    .line 62
    iget v2, v0, Ldm0/c;->g:I

    .line 63
    .line 64
    iget v6, v0, Ldm0/c;->f:I

    .line 65
    .line 66
    iget v7, v0, Ldm0/c;->e:I

    .line 67
    .line 68
    iget-object v8, v0, Ldm0/c;->d:Ld01/t0;

    .line 69
    .line 70
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catch Ljava/lang/Exception; {:try_start_0 .. :try_end_0} :catch_0

    .line 71
    .line 72
    .line 73
    goto/16 :goto_4

    .line 74
    .line 75
    :catch_0
    move-exception p2

    .line 76
    move-object v11, p2

    .line 77
    move p2, p1

    .line 78
    move p1, v6

    .line 79
    move v6, v2

    .line 80
    move-object v2, v0

    .line 81
    move-object v0, v11

    .line 82
    goto/16 :goto_5

    .line 83
    .line 84
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 85
    .line 86
    .line 87
    move v2, v3

    .line 88
    move v7, v4

    .line 89
    :goto_1
    if-ge v2, v7, :cond_c

    .line 90
    .line 91
    :try_start_1
    const-string p2, "Bearer"

    .line 92
    .line 93
    iget-object v6, p1, Ld01/t0;->d:Ld01/k0;

    .line 94
    .line 95
    const-string v8, "Authorization"

    .line 96
    .line 97
    iget-object v6, v6, Ld01/k0;->c:Ld01/y;

    .line 98
    .line 99
    invoke-virtual {v6, v8}, Ld01/y;->c(Ljava/lang/String;)Ljava/lang/String;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    const/4 v8, 0x0

    .line 104
    if-eqz v6, :cond_6

    .line 105
    .line 106
    invoke-static {v6, p2, v3}, Lly0/w;->x(Ljava/lang/String;Ljava/lang/String;Z)Z

    .line 107
    .line 108
    .line 109
    move-result v9

    .line 110
    if-eqz v9, :cond_6

    .line 111
    .line 112
    invoke-static {v6, p2}, Lly0/p;->S(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object p2

    .line 116
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 117
    .line 118
    .line 119
    move-result v6

    .line 120
    move v8, v3

    .line 121
    :goto_2
    if-ge v8, v6, :cond_5

    .line 122
    .line 123
    invoke-virtual {p2, v8}, Ljava/lang/String;->charAt(I)C

    .line 124
    .line 125
    .line 126
    move-result v9

    .line 127
    invoke-static {v9}, Lry/a;->d(C)Z

    .line 128
    .line 129
    .line 130
    move-result v9

    .line 131
    if-nez v9, :cond_4

    .line 132
    .line 133
    invoke-virtual {p2}, Ljava/lang/String;->length()I

    .line 134
    .line 135
    .line 136
    move-result v6

    .line 137
    invoke-virtual {p2, v8, v6}, Ljava/lang/String;->subSequence(II)Ljava/lang/CharSequence;

    .line 138
    .line 139
    .line 140
    move-result-object p2

    .line 141
    goto :goto_3

    .line 142
    :cond_4
    add-int/lit8 v8, v8, 0x1

    .line 143
    .line 144
    goto :goto_2

    .line 145
    :cond_5
    const-string p2, ""

    .line 146
    .line 147
    :goto_3
    invoke-virtual {p2}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object v8

    .line 151
    :cond_6
    iput-object p1, v0, Ldm0/c;->d:Ld01/t0;

    .line 152
    .line 153
    iput v7, v0, Ldm0/c;->e:I

    .line 154
    .line 155
    iput v2, v0, Ldm0/c;->f:I

    .line 156
    .line 157
    iput v2, v0, Ldm0/c;->g:I

    .line 158
    .line 159
    iput v3, v0, Ldm0/c;->h:I

    .line 160
    .line 161
    iput v5, v0, Ldm0/c;->k:I

    .line 162
    .line 163
    invoke-virtual {p0, v8, v0}, Lnc0/h;->c(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object p2
    :try_end_1
    .catch Ljava/lang/Exception; {:try_start_1 .. :try_end_1} :catch_1

    .line 167
    if-ne p2, v1, :cond_7

    .line 168
    .line 169
    goto :goto_6

    .line 170
    :cond_7
    move-object v8, p1

    .line 171
    move v6, v2

    .line 172
    move p1, v3

    .line 173
    :goto_4
    :try_start_2
    check-cast p2, Lne0/t;

    .line 174
    .line 175
    instance-of v9, p2, Lne0/e;

    .line 176
    .line 177
    if-eqz v9, :cond_8

    .line 178
    .line 179
    check-cast p2, Lne0/e;

    .line 180
    .line 181
    iget-object p2, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 182
    .line 183
    check-cast p2, Ljava/lang/String;

    .line 184
    .line 185
    move-object v1, p2

    .line 186
    goto :goto_6

    .line 187
    :cond_8
    instance-of v9, p2, Lne0/c;

    .line 188
    .line 189
    if-eqz v9, :cond_9

    .line 190
    .line 191
    check-cast p2, Lne0/c;

    .line 192
    .line 193
    iget-object p2, p2, Lne0/c;->a:Ljava/lang/Throwable;

    .line 194
    .line 195
    throw p2

    .line 196
    :cond_9
    new-instance p2, La8/r0;

    .line 197
    .line 198
    invoke-direct {p2}, Ljava/lang/RuntimeException;-><init>()V

    .line 199
    .line 200
    .line 201
    throw p2
    :try_end_2
    .catch Ljava/lang/Exception; {:try_start_2 .. :try_end_2} :catch_0

    .line 202
    :catch_1
    move-exception p2

    .line 203
    move-object v8, p1

    .line 204
    move p1, v2

    .line 205
    move v6, p1

    .line 206
    move-object v2, v0

    .line 207
    move-object v0, p2

    .line 208
    move p2, v3

    .line 209
    :goto_5
    invoke-static {v0}, Ljp/wa;->g(Ljava/lang/Throwable;)Z

    .line 210
    .line 211
    .line 212
    move-result v9

    .line 213
    if-nez v9, :cond_b

    .line 214
    .line 215
    iput-object v8, v2, Ldm0/c;->d:Ld01/t0;

    .line 216
    .line 217
    iput v7, v2, Ldm0/c;->e:I

    .line 218
    .line 219
    iput p1, v2, Ldm0/c;->f:I

    .line 220
    .line 221
    iput v6, v2, Ldm0/c;->g:I

    .line 222
    .line 223
    iput p2, v2, Ldm0/c;->h:I

    .line 224
    .line 225
    iput v4, v2, Ldm0/c;->k:I

    .line 226
    .line 227
    const-wide/16 v9, 0x2ee

    .line 228
    .line 229
    invoke-static {v9, v10, v2}, Lvy0/e0;->p(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 230
    .line 231
    .line 232
    move-result-object p2

    .line 233
    if-ne p2, v1, :cond_a

    .line 234
    .line 235
    :goto_6
    return-object v1

    .line 236
    :cond_a
    move-object v0, v2

    .line 237
    move-object v6, v8

    .line 238
    :goto_7
    add-int/lit8 v2, p1, 0x1

    .line 239
    .line 240
    move-object p1, v6

    .line 241
    goto/16 :goto_1

    .line 242
    .line 243
    :cond_b
    new-instance p1, Ld90/w;

    .line 244
    .line 245
    const/4 p2, 0x3

    .line 246
    invoke-direct {p1, p2, v8, v0}, Ld90/w;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 247
    .line 248
    .line 249
    invoke-static {p0, p1}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 250
    .line 251
    .line 252
    throw v0

    .line 253
    :cond_c
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 254
    .line 255
    const-string p1, "Max refresh token attempts acceded."

    .line 256
    .line 257
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 258
    .line 259
    .line 260
    throw p0
.end method


# virtual methods
.method public final a(Ld01/w0;Ld01/t0;)Ld01/k0;
    .locals 2

    .line 1
    new-instance p1, La7/o;

    .line 2
    .line 3
    const/16 v0, 0x1b

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    invoke-direct {p1, v0, p0, p2, v1}, La7/o;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 7
    .line 8
    .line 9
    sget-object p0, Lpx0/h;->d:Lpx0/h;

    .line 10
    .line 11
    invoke-static {p0, p1}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    check-cast p0, Ld01/k0;

    .line 16
    .line 17
    return-object p0
.end method

.method public final c(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p2, Lnc0/f;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lnc0/f;

    .line 7
    .line 8
    iget v1, v0, Lnc0/f;->f:I

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
    iput v1, v0, Lnc0/f;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lnc0/f;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lnc0/f;-><init>(Lnc0/h;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lnc0/f;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lnc0/f;->f:I

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 37
    .line 38
    .line 39
    goto :goto_2

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    if-eqz p1, :cond_3

    .line 52
    .line 53
    goto :goto_1

    .line 54
    :cond_3
    const/4 p1, 0x0

    .line 55
    :goto_1
    iput v3, v0, Lnc0/f;->f:I

    .line 56
    .line 57
    iget-object p0, p0, Lnc0/h;->c:Lkc0/u0;

    .line 58
    .line 59
    check-cast p0, Lic0/p;

    .line 60
    .line 61
    invoke-virtual {p0, p1, v0}, Lic0/p;->d(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object p2

    .line 65
    if-ne p2, v1, :cond_4

    .line 66
    .line 67
    return-object v1

    .line 68
    :cond_4
    :goto_2
    check-cast p2, Lne0/t;

    .line 69
    .line 70
    sget-object p0, Lnc0/g;->e:Lnc0/g;

    .line 71
    .line 72
    invoke-static {p2, p0}, Lbb/j0;->c(Lne0/t;Lay0/k;)Lne0/t;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method
