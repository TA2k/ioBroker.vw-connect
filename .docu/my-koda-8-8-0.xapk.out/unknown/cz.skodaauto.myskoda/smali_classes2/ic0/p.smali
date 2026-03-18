.class public final Lic0/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lkc0/g;
.implements Lkc0/h;


# instance fields
.field public final a:Llc0/l;

.field public final b:Lti0/a;

.field public final c:Lxl0/f;

.field public final d:Lti0/a;

.field public final e:Lyy0/c2;

.field public final f:Lyy0/c2;

.field public final g:Lez0/c;


# direct methods
.method public constructor <init>(Llc0/l;Lti0/a;Lxl0/f;Lti0/a;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lic0/p;->a:Llc0/l;

    .line 5
    .line 6
    iput-object p2, p0, Lic0/p;->b:Lti0/a;

    .line 7
    .line 8
    iput-object p3, p0, Lic0/p;->c:Lxl0/f;

    .line 9
    .line 10
    iput-object p4, p0, Lic0/p;->d:Lti0/a;

    .line 11
    .line 12
    const/4 p1, 0x0

    .line 13
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 14
    .line 15
    .line 16
    move-result-object p2

    .line 17
    iput-object p2, p0, Lic0/p;->e:Lyy0/c2;

    .line 18
    .line 19
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iput-object p1, p0, Lic0/p;->f:Lyy0/c2;

    .line 24
    .line 25
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    iput-object p1, p0, Lic0/p;->g:Lez0/c;

    .line 30
    .line 31
    return-void
.end method


# virtual methods
.method public final a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget-object v0, p0, Lic0/p;->e:Lyy0/c2;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 5
    .line 6
    .line 7
    iget-object v0, p0, Lic0/p;->f:Lyy0/c2;

    .line 8
    .line 9
    invoke-virtual {v0, v1}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    sget-object v0, Lge0/b;->a:Lcz0/e;

    .line 13
    .line 14
    new-instance v2, Lic0/g;

    .line 15
    .line 16
    const/4 v3, 0x0

    .line 17
    invoke-direct {v2, p0, v1, v3}, Lic0/g;-><init>(Lic0/p;Lkotlin/coroutines/Continuation;I)V

    .line 18
    .line 19
    .line 20
    invoke-static {v0, v2, p1}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p0

    .line 24
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 25
    .line 26
    if-ne p0, p1, :cond_0

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 30
    .line 31
    return-object p0
.end method

.method public final b()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lic0/p;->e:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Llc0/a;

    .line 8
    .line 9
    if-eqz p0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Llc0/a;->a:Ljava/lang/String;

    .line 12
    .line 13
    return-object p0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return-object p0
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 4

    .line 1
    instance-of v0, p1, Lic0/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lic0/k;

    .line 7
    .line 8
    iget v1, v0, Lic0/k;->f:I

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
    iput v1, v0, Lic0/k;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lic0/k;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lic0/k;-><init>(Lic0/p;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lic0/k;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lic0/k;->f:I

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
    iput v3, v0, Lic0/k;->f:I

    .line 52
    .line 53
    iget-object p1, p0, Lic0/p;->b:Lti0/a;

    .line 54
    .line 55
    invoke-interface {p1, v0}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object p1

    .line 59
    if-ne p1, v1, :cond_3

    .line 60
    .line 61
    return-object v1

    .line 62
    :cond_3
    :goto_1
    check-cast p1, Lic0/e;

    .line 63
    .line 64
    iget-object v0, p0, Lic0/p;->a:Llc0/l;

    .line 65
    .line 66
    iget-object v0, v0, Llc0/l;->d:Ljava/lang/String;

    .line 67
    .line 68
    iget-object p1, p1, Lic0/e;->a:Lla/u;

    .line 69
    .line 70
    const-string v1, "token"

    .line 71
    .line 72
    filled-new-array {v1}, [Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object v1

    .line 76
    new-instance v2, Lac0/r;

    .line 77
    .line 78
    const/16 v3, 0x1b

    .line 79
    .line 80
    invoke-direct {v2, v0, v3}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 81
    .line 82
    .line 83
    const/4 v0, 0x0

    .line 84
    invoke-static {p1, v0, v1, v2}, Ljp/ga;->a(Lla/u;Z[Ljava/lang/String;Lay0/k;)Lna/j;

    .line 85
    .line 86
    .line 87
    move-result-object p1

    .line 88
    new-instance v0, Lic0/i;

    .line 89
    .line 90
    const/4 v1, 0x1

    .line 91
    invoke-direct {v0, p1, v1}, Lic0/i;-><init>(Lna/j;I)V

    .line 92
    .line 93
    .line 94
    new-instance p1, Li50/y;

    .line 95
    .line 96
    const/4 v1, 0x0

    .line 97
    const/4 v2, 0x1

    .line 98
    invoke-direct {p1, p0, v1, v2}, Li50/y;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 99
    .line 100
    .line 101
    iget-object v1, p0, Lic0/p;->e:Lyy0/c2;

    .line 102
    .line 103
    iget-object p0, p0, Lic0/p;->f:Lyy0/c2;

    .line 104
    .line 105
    invoke-static {v0, v1, p0, p1}, Lyy0/u;->m(Lyy0/i;Lyy0/i;Lyy0/i;Lay0/p;)Lyy0/f1;

    .line 106
    .line 107
    .line 108
    move-result-object p0

    .line 109
    return-object p0
.end method

.method public final d(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p2, Lic0/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lic0/l;

    .line 7
    .line 8
    iget v1, v0, Lic0/l;->k:I

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
    iput v1, v0, Lic0/l;->k:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lic0/l;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lic0/l;-><init>(Lic0/p;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lic0/l;->i:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lic0/l;->k:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    const/4 v6, 0x0

    .line 35
    const/4 v7, 0x0

    .line 36
    if-eqz v2, :cond_4

    .line 37
    .line 38
    if-eq v2, v5, :cond_3

    .line 39
    .line 40
    if-eq v2, v4, :cond_2

    .line 41
    .line 42
    if-ne v2, v3, :cond_1

    .line 43
    .line 44
    iget-object p0, v0, Lic0/l;->f:Llc0/k;

    .line 45
    .line 46
    iget-object p1, v0, Lic0/l;->e:Lez0/a;

    .line 47
    .line 48
    :try_start_0
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 49
    .line 50
    .line 51
    goto/16 :goto_6

    .line 52
    .line 53
    :catchall_0
    move-exception v0

    .line 54
    move-object p0, v0

    .line 55
    goto/16 :goto_b

    .line 56
    .line 57
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 58
    .line 59
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 60
    .line 61
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 62
    .line 63
    .line 64
    throw p0

    .line 65
    :cond_2
    iget v6, v0, Lic0/l;->h:I

    .line 66
    .line 67
    iget p1, v0, Lic0/l;->g:I

    .line 68
    .line 69
    iget-object v2, v0, Lic0/l;->e:Lez0/a;

    .line 70
    .line 71
    :try_start_1
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 72
    .line 73
    .line 74
    move-object v9, v2

    .line 75
    move v2, p1

    .line 76
    :goto_1
    move-object p1, v9

    .line 77
    goto/16 :goto_4

    .line 78
    .line 79
    :catchall_1
    move-exception v0

    .line 80
    move-object p0, v0

    .line 81
    move-object p1, v2

    .line 82
    goto/16 :goto_b

    .line 83
    .line 84
    :cond_3
    iget p1, v0, Lic0/l;->g:I

    .line 85
    .line 86
    iget-object v2, v0, Lic0/l;->e:Lez0/a;

    .line 87
    .line 88
    iget-object v5, v0, Lic0/l;->d:Ljava/lang/String;

    .line 89
    .line 90
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    move-object p2, v2

    .line 94
    move v2, p1

    .line 95
    move-object p1, v5

    .line 96
    goto :goto_2

    .line 97
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 98
    .line 99
    .line 100
    iput-object p1, v0, Lic0/l;->d:Ljava/lang/String;

    .line 101
    .line 102
    iget-object p2, p0, Lic0/p;->g:Lez0/c;

    .line 103
    .line 104
    iput-object p2, v0, Lic0/l;->e:Lez0/a;

    .line 105
    .line 106
    iput v6, v0, Lic0/l;->g:I

    .line 107
    .line 108
    iput v5, v0, Lic0/l;->k:I

    .line 109
    .line 110
    invoke-virtual {p2, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v2

    .line 114
    if-ne v2, v1, :cond_5

    .line 115
    .line 116
    goto/16 :goto_5

    .line 117
    .line 118
    :cond_5
    move v2, v6

    .line 119
    :goto_2
    :try_start_2
    invoke-virtual {p0}, Lic0/p;->b()Ljava/lang/String;

    .line 120
    .line 121
    .line 122
    move-result-object v5

    .line 123
    if-eqz v5, :cond_7

    .line 124
    .line 125
    if-nez p1, :cond_6

    .line 126
    .line 127
    move p1, v6

    .line 128
    goto :goto_3

    .line 129
    :cond_6
    invoke-virtual {v5, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 130
    .line 131
    .line 132
    move-result p1

    .line 133
    :goto_3
    if-nez p1, :cond_7

    .line 134
    .line 135
    new-instance p0, Lne0/e;

    .line 136
    .line 137
    new-instance p1, Llc0/a;

    .line 138
    .line 139
    invoke-direct {p1, v5}, Llc0/a;-><init>(Ljava/lang/String;)V

    .line 140
    .line 141
    .line 142
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    goto/16 :goto_a

    .line 146
    .line 147
    :catchall_2
    move-exception v0

    .line 148
    move-object p0, v0

    .line 149
    move-object p1, p2

    .line 150
    goto/16 :goto_b

    .line 151
    .line 152
    :cond_7
    iput-object v7, v0, Lic0/l;->d:Ljava/lang/String;

    .line 153
    .line 154
    iput-object p2, v0, Lic0/l;->e:Lez0/a;

    .line 155
    .line 156
    iput v2, v0, Lic0/l;->g:I

    .line 157
    .line 158
    iput v6, v0, Lic0/l;->h:I

    .line 159
    .line 160
    iput v4, v0, Lic0/l;->k:I

    .line 161
    .line 162
    invoke-virtual {p0, v0}, Lic0/p;->e(Lrx0/c;)Ljava/lang/Object;

    .line 163
    .line 164
    .line 165
    move-result-object p1
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_2

    .line 166
    if-ne p1, v1, :cond_8

    .line 167
    .line 168
    goto :goto_5

    .line 169
    :cond_8
    move-object v9, p2

    .line 170
    move-object p2, p1

    .line 171
    goto :goto_1

    .line 172
    :goto_4
    :try_start_3
    check-cast p2, Lne0/t;

    .line 173
    .line 174
    instance-of v4, p2, Lne0/e;

    .line 175
    .line 176
    if-eqz v4, :cond_d

    .line 177
    .line 178
    check-cast p2, Lne0/e;

    .line 179
    .line 180
    iget-object p2, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 181
    .line 182
    check-cast p2, Llc0/k;

    .line 183
    .line 184
    iget-object v4, p2, Llc0/k;->b:Ljava/lang/String;

    .line 185
    .line 186
    if-eqz v4, :cond_c

    .line 187
    .line 188
    iget-object v5, p2, Llc0/k;->c:Ljava/lang/String;

    .line 189
    .line 190
    if-eqz v5, :cond_c

    .line 191
    .line 192
    iget-object v8, p2, Llc0/k;->d:Ljava/lang/String;

    .line 193
    .line 194
    if-nez v8, :cond_9

    .line 195
    .line 196
    goto :goto_8

    .line 197
    :cond_9
    iput-object v7, v0, Lic0/l;->d:Ljava/lang/String;

    .line 198
    .line 199
    iput-object p1, v0, Lic0/l;->e:Lez0/a;

    .line 200
    .line 201
    iput-object p2, v0, Lic0/l;->f:Llc0/k;

    .line 202
    .line 203
    iput v2, v0, Lic0/l;->g:I

    .line 204
    .line 205
    iput v6, v0, Lic0/l;->h:I

    .line 206
    .line 207
    iput v3, v0, Lic0/l;->k:I

    .line 208
    .line 209
    invoke-virtual {p0, v4, v5, v8, v0}, Lic0/p;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 210
    .line 211
    .line 212
    move-result-object p0

    .line 213
    if-ne p0, v1, :cond_a

    .line 214
    .line 215
    :goto_5
    return-object v1

    .line 216
    :cond_a
    move-object p0, p2

    .line 217
    :goto_6
    new-instance p2, Lne0/e;

    .line 218
    .line 219
    iget-object p0, p0, Llc0/k;->b:Ljava/lang/String;

    .line 220
    .line 221
    if-eqz p0, :cond_b

    .line 222
    .line 223
    new-instance v0, Llc0/a;

    .line 224
    .line 225
    invoke-direct {v0, p0}, Llc0/a;-><init>(Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    goto :goto_7

    .line 229
    :cond_b
    move-object v0, v7

    .line 230
    :goto_7
    invoke-direct {p2, v0}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 231
    .line 232
    .line 233
    move-object p0, p2

    .line 234
    move-object p2, p1

    .line 235
    goto :goto_a

    .line 236
    :cond_c
    :goto_8
    new-instance v0, Lne0/c;

    .line 237
    .line 238
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 239
    .line 240
    const-string p0, "Token bundle is incomplete. Some of the tokens are missing."

    .line 241
    .line 242
    invoke-direct {v1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 243
    .line 244
    .line 245
    const/4 v4, 0x0

    .line 246
    const/16 v5, 0x1e

    .line 247
    .line 248
    const/4 v2, 0x0

    .line 249
    const/4 v3, 0x0

    .line 250
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 251
    .line 252
    .line 253
    :goto_9
    move-object p2, p1

    .line 254
    move-object p0, v0

    .line 255
    goto :goto_a

    .line 256
    :cond_d
    instance-of p0, p2, Lne0/c;

    .line 257
    .line 258
    if-eqz p0, :cond_e

    .line 259
    .line 260
    new-instance v0, Lne0/c;

    .line 261
    .line 262
    move-object p0, p2

    .line 263
    check-cast p0, Lne0/c;

    .line 264
    .line 265
    iget-object v1, p0, Lne0/c;->a:Ljava/lang/Throwable;

    .line 266
    .line 267
    check-cast p2, Lne0/c;

    .line 268
    .line 269
    iget-object v2, p2, Lne0/c;->b:Lne0/c;

    .line 270
    .line 271
    const/4 v4, 0x0

    .line 272
    const/16 v5, 0x1c

    .line 273
    .line 274
    const/4 v3, 0x0

    .line 275
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 276
    .line 277
    .line 278
    goto :goto_9

    .line 279
    :goto_a
    invoke-interface {p2, v7}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 280
    .line 281
    .line 282
    return-object p0

    .line 283
    :cond_e
    :try_start_4
    new-instance p0, La8/r0;

    .line 284
    .line 285
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 286
    .line 287
    .line 288
    throw p0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 289
    :goto_b
    invoke-interface {p1, v7}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 290
    .line 291
    .line 292
    throw p0
.end method

.method public final e(Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p1, Lic0/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lic0/m;

    .line 7
    .line 8
    iget v1, v0, Lic0/m;->h:I

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
    iput v1, v0, Lic0/m;->h:I

    .line 18
    .line 19
    :goto_0
    move-object p1, v0

    .line 20
    goto :goto_1

    .line 21
    :cond_0
    new-instance v0, Lic0/m;

    .line 22
    .line 23
    invoke-direct {v0, p0, p1}, Lic0/m;-><init>(Lic0/p;Lrx0/c;)V

    .line 24
    .line 25
    .line 26
    goto :goto_0

    .line 27
    :goto_1
    iget-object v0, p1, Lic0/m;->f:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v2, p1, Lic0/m;->h:I

    .line 32
    .line 33
    const/4 v3, 0x0

    .line 34
    const/4 v4, 0x3

    .line 35
    const/4 v5, 0x2

    .line 36
    const/4 v6, 0x1

    .line 37
    const/4 v7, 0x0

    .line 38
    if-eqz v2, :cond_4

    .line 39
    .line 40
    if-eq v2, v6, :cond_3

    .line 41
    .line 42
    if-eq v2, v5, :cond_2

    .line 43
    .line 44
    if-ne v2, v4, :cond_1

    .line 45
    .line 46
    iget-object p1, p1, Lic0/m;->d:Lic0/p;

    .line 47
    .line 48
    check-cast p1, Lic0/f;

    .line 49
    .line 50
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    goto/16 :goto_7

    .line 54
    .line 55
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 56
    .line 57
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 58
    .line 59
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 60
    .line 61
    .line 62
    throw p0

    .line 63
    :cond_2
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 64
    .line 65
    .line 66
    goto :goto_3

    .line 67
    :catchall_0
    move-exception v0

    .line 68
    goto :goto_4

    .line 69
    :cond_3
    iget v2, p1, Lic0/m;->e:I

    .line 70
    .line 71
    iget-object v8, p1, Lic0/m;->d:Lic0/p;

    .line 72
    .line 73
    :try_start_1
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 74
    .line 75
    .line 76
    goto :goto_2

    .line 77
    :cond_4
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    :try_start_2
    iget-object v0, p0, Lic0/p;->b:Lti0/a;

    .line 81
    .line 82
    iput-object p0, p1, Lic0/m;->d:Lic0/p;

    .line 83
    .line 84
    iput v3, p1, Lic0/m;->e:I

    .line 85
    .line 86
    iput v6, p1, Lic0/m;->h:I

    .line 87
    .line 88
    invoke-interface {v0, p1}, Lti0/a;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v0

    .line 92
    if-ne v0, v1, :cond_5

    .line 93
    .line 94
    goto :goto_6

    .line 95
    :cond_5
    move-object v8, p0

    .line 96
    move v2, v3

    .line 97
    :goto_2
    check-cast v0, Lic0/e;

    .line 98
    .line 99
    iget-object v8, v8, Lic0/p;->a:Llc0/l;

    .line 100
    .line 101
    iget-object v8, v8, Llc0/l;->d:Ljava/lang/String;

    .line 102
    .line 103
    iput-object v7, p1, Lic0/m;->d:Lic0/p;

    .line 104
    .line 105
    iput v2, p1, Lic0/m;->e:I

    .line 106
    .line 107
    iput v5, p1, Lic0/m;->h:I

    .line 108
    .line 109
    iget-object v0, v0, Lic0/e;->a:Lla/u;

    .line 110
    .line 111
    new-instance v2, Lac0/r;

    .line 112
    .line 113
    const/16 v5, 0x1c

    .line 114
    .line 115
    invoke-direct {v2, v8, v5}, Lac0/r;-><init>(Ljava/lang/String;I)V

    .line 116
    .line 117
    .line 118
    invoke-static {p1, v0, v6, v3, v2}, Ljp/ue;->h(Lkotlin/coroutines/Continuation;Lla/u;ZZLay0/k;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object v0

    .line 122
    if-ne v0, v1, :cond_6

    .line 123
    .line 124
    goto :goto_6

    .line 125
    :cond_6
    :goto_3
    check-cast v0, Lic0/f;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 126
    .line 127
    goto :goto_5

    .line 128
    :goto_4
    invoke-static {v0}, Lps/t1;->a(Ljava/lang/Throwable;)Llx0/n;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    :goto_5
    instance-of v2, v0, Llx0/n;

    .line 133
    .line 134
    if-eqz v2, :cond_7

    .line 135
    .line 136
    move-object v0, v7

    .line 137
    :cond_7
    check-cast v0, Lic0/f;

    .line 138
    .line 139
    if-eqz v0, :cond_9

    .line 140
    .line 141
    new-instance v2, La2/c;

    .line 142
    .line 143
    const/16 v5, 0x12

    .line 144
    .line 145
    invoke-direct {v2, v5, p0, v0, v7}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 146
    .line 147
    .line 148
    new-instance v0, Li40/e1;

    .line 149
    .line 150
    const/16 v5, 0x8

    .line 151
    .line 152
    invoke-direct {v0, p0, v5}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 153
    .line 154
    .line 155
    iput-object v7, p1, Lic0/m;->d:Lic0/p;

    .line 156
    .line 157
    iput v3, p1, Lic0/m;->e:I

    .line 158
    .line 159
    iput v4, p1, Lic0/m;->h:I

    .line 160
    .line 161
    iget-object v3, p0, Lic0/p;->c:Lxl0/f;

    .line 162
    .line 163
    invoke-virtual {v3, v2, v0, v7, p1}, Lxl0/f;->g(Lay0/k;Lay0/k;Lay0/k;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object v0

    .line 167
    if-ne v0, v1, :cond_8

    .line 168
    .line 169
    :goto_6
    return-object v1

    .line 170
    :cond_8
    :goto_7
    check-cast v0, Lne0/t;

    .line 171
    .line 172
    if-eqz v0, :cond_9

    .line 173
    .line 174
    goto :goto_8

    .line 175
    :cond_9
    new-instance v1, Lne0/c;

    .line 176
    .line 177
    new-instance v2, Lbm0/b;

    .line 178
    .line 179
    iget-object p0, p0, Lic0/p;->a:Llc0/l;

    .line 180
    .line 181
    iget-object p0, p0, Llc0/l;->d:Ljava/lang/String;

    .line 182
    .line 183
    new-instance p1, Ljava/lang/StringBuilder;

    .line 184
    .line 185
    const-string v0, "Refresh token for "

    .line 186
    .line 187
    invoke-direct {p1, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 188
    .line 189
    .line 190
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 191
    .line 192
    .line 193
    const-string p0, " token type has not been found."

    .line 194
    .line 195
    invoke-virtual {p1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 196
    .line 197
    .line 198
    invoke-virtual {p1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 199
    .line 200
    .line 201
    move-result-object p0

    .line 202
    const-string p1, "message"

    .line 203
    .line 204
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 205
    .line 206
    .line 207
    invoke-direct {v2, p0}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 208
    .line 209
    .line 210
    const/4 v5, 0x0

    .line 211
    const/16 v6, 0x1e

    .line 212
    .line 213
    const/4 v3, 0x0

    .line 214
    const/4 v4, 0x0

    .line 215
    invoke-direct/range {v1 .. v6}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 216
    .line 217
    .line 218
    move-object v0, v1

    .line 219
    :goto_8
    return-object v0
.end method

.method public final f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p4, Lic0/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p4

    .line 6
    check-cast v0, Lic0/o;

    .line 7
    .line 8
    iget v1, v0, Lic0/o;->h:I

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
    iput v1, v0, Lic0/o;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lic0/o;

    .line 21
    .line 22
    invoke-direct {v0, p0, p4}, Lic0/o;-><init>(Lic0/p;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p4, v0, Lic0/o;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lic0/o;->h:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    if-eqz v2, :cond_2

    .line 34
    .line 35
    if-ne v2, v3, :cond_1

    .line 36
    .line 37
    iget-object p3, v0, Lic0/o;->e:Ljava/lang/String;

    .line 38
    .line 39
    iget-object p1, v0, Lic0/o;->d:Ljava/lang/String;

    .line 40
    .line 41
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    goto :goto_1

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
    invoke-static {p4}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    sget-object p4, Lge0/b;->a:Lcz0/e;

    .line 57
    .line 58
    new-instance v2, Lic0/n;

    .line 59
    .line 60
    const/4 v5, 0x1

    .line 61
    invoke-direct {v2, p0, p2, v4, v5}, Lic0/n;-><init>(Lic0/p;Ljava/lang/String;Lkotlin/coroutines/Continuation;I)V

    .line 62
    .line 63
    .line 64
    iput-object p1, v0, Lic0/o;->d:Ljava/lang/String;

    .line 65
    .line 66
    iput-object p3, v0, Lic0/o;->e:Ljava/lang/String;

    .line 67
    .line 68
    iput v3, v0, Lic0/o;->h:I

    .line 69
    .line 70
    invoke-static {p4, v2, v0}, Lvy0/e0;->R(Lpx0/g;Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p2

    .line 74
    if-ne p2, v1, :cond_3

    .line 75
    .line 76
    return-object v1

    .line 77
    :cond_3
    :goto_1
    new-instance p2, Llc0/a;

    .line 78
    .line 79
    invoke-direct {p2, p1}, Llc0/a;-><init>(Ljava/lang/String;)V

    .line 80
    .line 81
    .line 82
    iget-object p1, p0, Lic0/p;->e:Lyy0/c2;

    .line 83
    .line 84
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 85
    .line 86
    .line 87
    invoke-virtual {p1, v4, p2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 88
    .line 89
    .line 90
    new-instance p1, Llc0/d;

    .line 91
    .line 92
    invoke-direct {p1, p3}, Llc0/d;-><init>(Ljava/lang/String;)V

    .line 93
    .line 94
    .line 95
    iget-object p0, p0, Lic0/p;->f:Lyy0/c2;

    .line 96
    .line 97
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 98
    .line 99
    .line 100
    invoke-virtual {p0, v4, p1}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 101
    .line 102
    .line 103
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 104
    .line 105
    return-object p0
.end method
