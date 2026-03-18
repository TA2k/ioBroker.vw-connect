.class public final Lnc0/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ldm0/l;


# instance fields
.field public final a:Lkc0/u0;

.field public final b:Lwr0/e;

.field public final c:Lkc0/t0;


# direct methods
.method public constructor <init>(Lkc0/u0;Lwr0/e;Lkc0/t0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lnc0/r;->a:Lkc0/u0;

    .line 5
    .line 6
    iput-object p2, p0, Lnc0/r;->b:Lwr0/e;

    .line 7
    .line 8
    iput-object p3, p0, Lnc0/r;->c:Lkc0/t0;

    .line 9
    .line 10
    return-void
.end method

.method public static final b(Lnc0/r;Ld01/k0;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Lnc0/r;->a:Lkc0/u0;

    .line 2
    .line 3
    instance-of v1, p2, Lnc0/q;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p2

    .line 8
    check-cast v1, Lnc0/q;

    .line 9
    .line 10
    iget v2, v1, Lnc0/q;->j:I

    .line 11
    .line 12
    const/high16 v3, -0x80000000

    .line 13
    .line 14
    and-int v4, v2, v3

    .line 15
    .line 16
    if-eqz v4, :cond_0

    .line 17
    .line 18
    sub-int/2addr v2, v3

    .line 19
    iput v2, v1, Lnc0/q;->j:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lnc0/q;

    .line 23
    .line 24
    invoke-direct {v1, p0, p2}, Lnc0/q;-><init>(Lnc0/r;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p2, v1, Lnc0/q;->h:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lnc0/q;->j:I

    .line 32
    .line 33
    const/4 v4, 0x3

    .line 34
    const/4 v5, 0x2

    .line 35
    const/4 v6, 0x1

    .line 36
    const/4 v7, 0x0

    .line 37
    if-eqz v3, :cond_4

    .line 38
    .line 39
    if-eq v3, v6, :cond_3

    .line 40
    .line 41
    if-eq v3, v5, :cond_2

    .line 42
    .line 43
    if-eq v3, v4, :cond_1

    .line 44
    .line 45
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
    :cond_1
    iget-object p0, v1, Lnc0/q;->f:Lne0/t;

    .line 54
    .line 55
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    goto/16 :goto_5

    .line 59
    .line 60
    :cond_2
    iget p0, v1, Lnc0/q;->g:I

    .line 61
    .line 62
    iget-object p1, v1, Lnc0/q;->f:Lne0/t;

    .line 63
    .line 64
    iget-object v0, v1, Lnc0/q;->e:Lnc0/r;

    .line 65
    .line 66
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 67
    .line 68
    .line 69
    move-object v9, p2

    .line 70
    move p2, p0

    .line 71
    move-object p0, p1

    .line 72
    move-object p1, v9

    .line 73
    goto/16 :goto_3

    .line 74
    .line 75
    :cond_3
    iget p0, v1, Lnc0/q;->g:I

    .line 76
    .line 77
    iget-object p1, v1, Lnc0/q;->e:Lnc0/r;

    .line 78
    .line 79
    iget-object v0, v1, Lnc0/q;->d:Ld01/k0;

    .line 80
    .line 81
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    move-object v9, p2

    .line 85
    move p2, p0

    .line 86
    move-object p0, p1

    .line 87
    move-object p1, v0

    .line 88
    move-object v0, v9

    .line 89
    goto :goto_1

    .line 90
    :cond_4
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    check-cast v0, Lic0/p;

    .line 94
    .line 95
    invoke-virtual {v0}, Lic0/p;->b()Ljava/lang/String;

    .line 96
    .line 97
    .line 98
    move-result-object p2

    .line 99
    if-nez p2, :cond_d

    .line 100
    .line 101
    iput-object p1, v1, Lnc0/q;->d:Ld01/k0;

    .line 102
    .line 103
    iput-object p0, v1, Lnc0/q;->e:Lnc0/r;

    .line 104
    .line 105
    const/4 p2, 0x0

    .line 106
    iput p2, v1, Lnc0/q;->g:I

    .line 107
    .line 108
    iput v6, v1, Lnc0/q;->j:I

    .line 109
    .line 110
    invoke-virtual {v0, v7, v1}, Lic0/p;->d(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object v0

    .line 114
    if-ne v0, v2, :cond_5

    .line 115
    .line 116
    goto/16 :goto_4

    .line 117
    .line 118
    :cond_5
    :goto_1
    check-cast v0, Lne0/t;

    .line 119
    .line 120
    instance-of v3, v0, Lne0/e;

    .line 121
    .line 122
    if-eqz v3, :cond_8

    .line 123
    .line 124
    new-instance p1, Lmz0/b;

    .line 125
    .line 126
    const/16 p2, 0x16

    .line 127
    .line 128
    invoke-direct {p1, p2}, Lmz0/b;-><init>(I)V

    .line 129
    .line 130
    .line 131
    const-string p2, "Authentication"

    .line 132
    .line 133
    invoke-static {p2, p0, p1}, Llp/nd;->f(Ljava/lang/String;Ljava/lang/Object;Lay0/a;)Lkj0/f;

    .line 134
    .line 135
    .line 136
    iget-object p0, p0, Lnc0/r;->a:Lkc0/u0;

    .line 137
    .line 138
    check-cast p0, Lic0/p;

    .line 139
    .line 140
    invoke-virtual {p0}, Lic0/p;->b()Ljava/lang/String;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    if-eqz p0, :cond_6

    .line 145
    .line 146
    new-instance p1, Llc0/a;

    .line 147
    .line 148
    invoke-direct {p1, p0}, Llc0/a;-><init>(Ljava/lang/String;)V

    .line 149
    .line 150
    .line 151
    goto :goto_2

    .line 152
    :cond_6
    move-object p1, v7

    .line 153
    :goto_2
    if-eqz p1, :cond_7

    .line 154
    .line 155
    iget-object p0, p1, Llc0/a;->a:Ljava/lang/String;

    .line 156
    .line 157
    return-object p0

    .line 158
    :cond_7
    return-object v7

    .line 159
    :cond_8
    instance-of v3, v0, Lne0/c;

    .line 160
    .line 161
    if-eqz v3, :cond_c

    .line 162
    .line 163
    new-instance v3, Llk/j;

    .line 164
    .line 165
    move-object v6, v0

    .line 166
    check-cast v6, Lne0/c;

    .line 167
    .line 168
    const/16 v8, 0x14

    .line 169
    .line 170
    invoke-direct {v3, v8, v6, p1}, Llk/j;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    invoke-static {p0, v3}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 174
    .line 175
    .line 176
    iget-object p1, v6, Lne0/c;->a:Ljava/lang/Throwable;

    .line 177
    .line 178
    invoke-static {p1}, Ljp/wa;->g(Ljava/lang/Throwable;)Z

    .line 179
    .line 180
    .line 181
    move-result p1

    .line 182
    if-eqz p1, :cond_b

    .line 183
    .line 184
    iget-object p1, p0, Lnc0/r;->b:Lwr0/e;

    .line 185
    .line 186
    iput-object v7, v1, Lnc0/q;->d:Ld01/k0;

    .line 187
    .line 188
    iput-object p0, v1, Lnc0/q;->e:Lnc0/r;

    .line 189
    .line 190
    iput-object v0, v1, Lnc0/q;->f:Lne0/t;

    .line 191
    .line 192
    iput p2, v1, Lnc0/q;->g:I

    .line 193
    .line 194
    iput v5, v1, Lnc0/q;->j:I

    .line 195
    .line 196
    iget-object p1, p1, Lwr0/e;->a:Lwr0/g;

    .line 197
    .line 198
    check-cast p1, Lur0/g;

    .line 199
    .line 200
    invoke-virtual {p1, v1}, Lur0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 201
    .line 202
    .line 203
    move-result-object p1

    .line 204
    if-ne p1, v2, :cond_9

    .line 205
    .line 206
    goto :goto_4

    .line 207
    :cond_9
    move-object v9, v0

    .line 208
    move-object v0, p0

    .line 209
    move-object p0, v9

    .line 210
    :goto_3
    if-eqz p1, :cond_a

    .line 211
    .line 212
    iget-object p1, v0, Lnc0/r;->c:Lkc0/t0;

    .line 213
    .line 214
    iput-object v7, v1, Lnc0/q;->d:Ld01/k0;

    .line 215
    .line 216
    iput-object v7, v1, Lnc0/q;->e:Lnc0/r;

    .line 217
    .line 218
    iput-object p0, v1, Lnc0/q;->f:Lne0/t;

    .line 219
    .line 220
    iput p2, v1, Lnc0/q;->g:I

    .line 221
    .line 222
    iput v4, v1, Lnc0/q;->j:I

    .line 223
    .line 224
    invoke-virtual {p1, p0, v1}, Lkc0/t0;->b(Lne0/t;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 225
    .line 226
    .line 227
    move-result-object p1

    .line 228
    if-ne p1, v2, :cond_a

    .line 229
    .line 230
    :goto_4
    return-object v2

    .line 231
    :cond_a
    :goto_5
    move-object v0, p0

    .line 232
    :cond_b
    new-instance p0, Ljava/io/IOException;

    .line 233
    .line 234
    check-cast v0, Lne0/c;

    .line 235
    .line 236
    iget-object p1, v0, Lne0/c;->a:Ljava/lang/Throwable;

    .line 237
    .line 238
    const-string p2, "Unable to refresh access token"

    .line 239
    .line 240
    invoke-direct {p0, p2, p1}, Ljava/io/IOException;-><init>(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 241
    .line 242
    .line 243
    throw p0

    .line 244
    :cond_c
    new-instance p0, La8/r0;

    .line 245
    .line 246
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 247
    .line 248
    .line 249
    throw p0

    .line 250
    :cond_d
    return-object p2
.end method


# virtual methods
.method public final a(Lcm0/b;Ld01/k0;)Ld01/k0;
    .locals 2

    .line 1
    const-string v0, "environment"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "request"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    sget-object v0, Lcm0/b;->g:Lcm0/b;

    .line 12
    .line 13
    if-ne p1, v0, :cond_0

    .line 14
    .line 15
    return-object p2

    .line 16
    :cond_0
    new-instance p1, Lna/e;

    .line 17
    .line 18
    const/4 v0, 0x2

    .line 19
    const/4 v1, 0x0

    .line 20
    invoke-direct {p1, v0, p0, p2, v1}, Lna/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 21
    .line 22
    .line 23
    sget-object p0, Lpx0/h;->d:Lpx0/h;

    .line 24
    .line 25
    invoke-static {p0, p1}, Lvy0/e0;->K(Lpx0/g;Lay0/n;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    check-cast p0, Llc0/a;

    .line 30
    .line 31
    if-eqz p0, :cond_1

    .line 32
    .line 33
    iget-object p0, p0, Llc0/a;->a:Ljava/lang/String;

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_1
    move-object p0, v1

    .line 37
    :goto_0
    if-nez p0, :cond_2

    .line 38
    .line 39
    goto :goto_1

    .line 40
    :cond_2
    move-object v1, p0

    .line 41
    :goto_1
    invoke-virtual {p2}, Ld01/k0;->b()Ld01/j0;

    .line 42
    .line 43
    .line 44
    move-result-object p0

    .line 45
    if-nez v1, :cond_3

    .line 46
    .line 47
    const-string v1, ""

    .line 48
    .line 49
    :cond_3
    const-string p1, "Bearer "

    .line 50
    .line 51
    invoke-virtual {p1, v1}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p1

    .line 55
    const-string p2, "Authorization"

    .line 56
    .line 57
    invoke-virtual {p0, p2, p1}, Ld01/j0;->c(Ljava/lang/String;Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    new-instance p1, Ld01/k0;

    .line 61
    .line 62
    invoke-direct {p1, p0}, Ld01/k0;-><init>(Ld01/j0;)V

    .line 63
    .line 64
    .line 65
    return-object p1
.end method
