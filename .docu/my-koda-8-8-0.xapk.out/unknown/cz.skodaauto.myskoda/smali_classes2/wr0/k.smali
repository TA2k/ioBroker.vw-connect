.class public final Lwr0/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lam0/c;

.field public final b:Lwr0/e;

.field public final c:Lbd0/c;


# direct methods
.method public constructor <init>(Lam0/c;Lbd0/c;Lwr0/e;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwr0/k;->a:Lam0/c;

    .line 5
    .line 6
    iput-object p3, p0, Lwr0/k;->b:Lwr0/e;

    .line 7
    .line 8
    iput-object p2, p0, Lwr0/k;->c:Lbd0/c;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lwr0/k;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p1, Lwr0/j;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lwr0/j;

    .line 7
    .line 8
    iget v1, v0, Lwr0/j;->h:I

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
    iput v1, v0, Lwr0/j;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwr0/j;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lwr0/j;-><init>(Lwr0/k;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lwr0/j;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwr0/j;->h:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    if-eqz v2, :cond_3

    .line 34
    .line 35
    if-eq v2, v4, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    iget-object v1, v0, Lwr0/j;->e:Ld01/z;

    .line 40
    .line 41
    iget-object v0, v0, Lwr0/j;->d:Ljava/lang/String;

    .line 42
    .line 43
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    move-object v5, v1

    .line 47
    goto :goto_3

    .line 48
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 49
    .line 50
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 51
    .line 52
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 53
    .line 54
    .line 55
    throw p0

    .line 56
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    iput v4, v0, Lwr0/j;->h:I

    .line 64
    .line 65
    iget-object p1, p0, Lwr0/k;->b:Lwr0/e;

    .line 66
    .line 67
    iget-object p1, p1, Lwr0/e;->a:Lwr0/g;

    .line 68
    .line 69
    check-cast p1, Lur0/g;

    .line 70
    .line 71
    invoke-virtual {p1, v0}, Lur0/g;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    if-ne p1, v1, :cond_4

    .line 76
    .line 77
    goto :goto_2

    .line 78
    :cond_4
    :goto_1
    check-cast p1, Lyr0/e;

    .line 79
    .line 80
    if-eqz p1, :cond_a

    .line 81
    .line 82
    iget-object p1, p1, Lyr0/e;->b:Ljava/lang/String;

    .line 83
    .line 84
    if-eqz p1, :cond_a

    .line 85
    .line 86
    new-instance v2, Ld01/z;

    .line 87
    .line 88
    const/4 v5, 0x0

    .line 89
    invoke-direct {v2, v5}, Ld01/z;-><init>(I)V

    .line 90
    .line 91
    .line 92
    const-string v5, "https"

    .line 93
    .line 94
    invoke-virtual {v2, v5}, Ld01/z;->k(Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    iput-object p1, v0, Lwr0/j;->d:Ljava/lang/String;

    .line 98
    .line 99
    iput-object v2, v0, Lwr0/j;->e:Ld01/z;

    .line 100
    .line 101
    iput v3, v0, Lwr0/j;->h:I

    .line 102
    .line 103
    iget-object v5, p0, Lwr0/k;->a:Lam0/c;

    .line 104
    .line 105
    iget-object v5, v5, Lam0/c;->a:Lam0/b;

    .line 106
    .line 107
    check-cast v5, Lxl0/o;

    .line 108
    .line 109
    invoke-virtual {v5, v0}, Lxl0/o;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Enum;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    if-ne v0, v1, :cond_5

    .line 114
    .line 115
    :goto_2
    return-object v1

    .line 116
    :cond_5
    move-object v5, v0

    .line 117
    move-object v0, p1

    .line 118
    move-object p1, v5

    .line 119
    move-object v5, v2

    .line 120
    :goto_3
    check-cast p1, Lcm0/b;

    .line 121
    .line 122
    invoke-static {p1}, Lcom/google/android/gms/internal/measurement/i5;->c(Lcm0/b;)Ljava/lang/String;

    .line 123
    .line 124
    .line 125
    move-result-object p1

    .line 126
    invoke-virtual {v5, p1}, Ld01/z;->f(Ljava/lang/String;)V

    .line 127
    .line 128
    .line 129
    const/4 v9, 0x0

    .line 130
    const/4 v10, 0x0

    .line 131
    const/4 v6, 0x0

    .line 132
    const/4 v7, 0x7

    .line 133
    const-string v8, "account"

    .line 134
    .line 135
    invoke-virtual/range {v5 .. v10}, Ld01/z;->i(IILjava/lang/String;ZZ)V

    .line 136
    .line 137
    .line 138
    const-string p1, "login_hint"

    .line 139
    .line 140
    invoke-virtual {v5, p1, v0}, Ld01/z;->a(Ljava/lang/String;Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    invoke-virtual {v5}, Ld01/z;->c()Ld01/a0;

    .line 144
    .line 145
    .line 146
    move-result-object p1

    .line 147
    invoke-virtual {p1}, Ld01/a0;->k()Ljava/net/URL;

    .line 148
    .line 149
    .line 150
    move-result-object p1

    .line 151
    invoke-virtual {p1}, Ljava/net/URL;->toString()Ljava/lang/String;

    .line 152
    .line 153
    .line 154
    move-result-object p1

    .line 155
    const-string v0, "toString(...)"

    .line 156
    .line 157
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    const/16 v0, 0x18

    .line 161
    .line 162
    and-int/lit8 v1, v0, 0x2

    .line 163
    .line 164
    const/4 v2, 0x0

    .line 165
    if-eqz v1, :cond_6

    .line 166
    .line 167
    move v7, v4

    .line 168
    goto :goto_4

    .line 169
    :cond_6
    move v7, v2

    .line 170
    :goto_4
    and-int/lit8 v1, v0, 0x4

    .line 171
    .line 172
    if-eqz v1, :cond_7

    .line 173
    .line 174
    move v8, v4

    .line 175
    goto :goto_5

    .line 176
    :cond_7
    move v8, v2

    .line 177
    :goto_5
    and-int/lit8 v1, v0, 0x8

    .line 178
    .line 179
    if-eqz v1, :cond_8

    .line 180
    .line 181
    move v9, v2

    .line 182
    goto :goto_6

    .line 183
    :cond_8
    move v9, v4

    .line 184
    :goto_6
    and-int/lit8 v0, v0, 0x10

    .line 185
    .line 186
    if-eqz v0, :cond_9

    .line 187
    .line 188
    move v10, v2

    .line 189
    goto :goto_7

    .line 190
    :cond_9
    move v10, v4

    .line 191
    :goto_7
    iget-object p0, p0, Lwr0/k;->c:Lbd0/c;

    .line 192
    .line 193
    iget-object p0, p0, Lbd0/c;->a:Lbd0/a;

    .line 194
    .line 195
    new-instance v6, Ljava/net/URL;

    .line 196
    .line 197
    invoke-direct {v6, p1}, Ljava/net/URL;-><init>(Ljava/lang/String;)V

    .line 198
    .line 199
    .line 200
    move-object v5, p0

    .line 201
    check-cast v5, Lzc0/b;

    .line 202
    .line 203
    invoke-virtual/range {v5 .. v10}, Lzc0/b;->b(Ljava/net/URL;ZZZZ)Lyy0/m1;

    .line 204
    .line 205
    .line 206
    move-result-object p0

    .line 207
    return-object p0

    .line 208
    :cond_a
    new-instance v0, Lne0/c;

    .line 209
    .line 210
    new-instance v1, Ljava/lang/Exception;

    .line 211
    .line 212
    const-string p1, "User email is not available"

    .line 213
    .line 214
    invoke-direct {v1, p1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    const/4 v4, 0x0

    .line 218
    const/16 v5, 0x1e

    .line 219
    .line 220
    const/4 v2, 0x0

    .line 221
    const/4 v3, 0x0

    .line 222
    invoke-direct/range {v0 .. v5}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 223
    .line 224
    .line 225
    new-instance p1, La60/a;

    .line 226
    .line 227
    const/4 v1, 0x1

    .line 228
    invoke-direct {p1, v0, v1}, La60/a;-><init>(Lne0/c;I)V

    .line 229
    .line 230
    .line 231
    invoke-static {p0, p1}, Llp/nd;->e(Ljava/lang/Object;Lay0/a;)V

    .line 232
    .line 233
    .line 234
    new-instance p0, Lyy0/m;

    .line 235
    .line 236
    const/4 p1, 0x0

    .line 237
    invoke-direct {p0, v0, p1}, Lyy0/m;-><init>(Ljava/lang/Object;I)V

    .line 238
    .line 239
    .line 240
    return-object p0
.end method
