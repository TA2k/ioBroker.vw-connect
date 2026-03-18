.class public final Lpp0/r1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lpp0/c0;


# direct methods
.method public constructor <init>(Lpp0/c0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lpp0/r1;->a:Lpp0/c0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Lqp0/x;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2}, Lpp0/r1;->b(Lqp0/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lqp0/x;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p2, Lpp0/q1;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lpp0/q1;

    .line 7
    .line 8
    iget v1, v0, Lpp0/q1;->g:I

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
    iput v1, v0, Lpp0/q1;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lpp0/q1;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lpp0/q1;-><init>(Lpp0/r1;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lpp0/q1;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lpp0/q1;->g:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    iget-object p0, p0, Lpp0/r1;->a:Lpp0/c0;

    .line 34
    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v4, :cond_2

    .line 38
    .line 39
    if-ne v2, v3, :cond_1

    .line 40
    .line 41
    iget-object p1, v0, Lpp0/q1;->d:Lqp0/x;

    .line 42
    .line 43
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 44
    .line 45
    .line 46
    goto :goto_4

    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    iget-object p1, v0, Lpp0/q1;->d:Lqp0/x;

    .line 56
    .line 57
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    move-object p2, p0

    .line 65
    check-cast p2, Lnp0/b;

    .line 66
    .line 67
    iget-object p2, p2, Lnp0/b;->i:Lyy0/l1;

    .line 68
    .line 69
    iput-object p1, v0, Lpp0/q1;->d:Lqp0/x;

    .line 70
    .line 71
    iput v4, v0, Lpp0/q1;->g:I

    .line 72
    .line 73
    invoke-static {p2, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object p2

    .line 77
    if-ne p2, v1, :cond_4

    .line 78
    .line 79
    goto :goto_3

    .line 80
    :cond_4
    :goto_1
    check-cast p2, Lqp0/g;

    .line 81
    .line 82
    const/4 v2, 0x0

    .line 83
    if-eqz p2, :cond_5

    .line 84
    .line 85
    iget-object p2, p2, Lqp0/g;->a:Ljava/util/List;

    .line 86
    .line 87
    goto :goto_2

    .line 88
    :cond_5
    move-object p2, v2

    .line 89
    :goto_2
    if-nez p2, :cond_7

    .line 90
    .line 91
    move-object p2, p0

    .line 92
    check-cast p2, Lnp0/b;

    .line 93
    .line 94
    iget-object p2, p2, Lnp0/b;->c:Lyy0/l1;

    .line 95
    .line 96
    iput-object p1, v0, Lpp0/q1;->d:Lqp0/x;

    .line 97
    .line 98
    iput v3, v0, Lpp0/q1;->g:I

    .line 99
    .line 100
    invoke-static {p2, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 101
    .line 102
    .line 103
    move-result-object p2

    .line 104
    if-ne p2, v1, :cond_6

    .line 105
    .line 106
    :goto_3
    return-object v1

    .line 107
    :cond_6
    :goto_4
    check-cast p2, Lqp0/p;

    .line 108
    .line 109
    if-eqz p2, :cond_d

    .line 110
    .line 111
    invoke-static {p1}, Ljp/dg;->b(Lqp0/x;)Lqp0/b0;

    .line 112
    .line 113
    .line 114
    move-result-object p1

    .line 115
    invoke-static {p1}, Ljp/k1;->i(Ljava/lang/Object;)Ljava/util/List;

    .line 116
    .line 117
    .line 118
    move-result-object p1

    .line 119
    check-cast p1, Ljava/util/Collection;

    .line 120
    .line 121
    iget-object p2, p2, Lqp0/p;->a:Ljava/util/List;

    .line 122
    .line 123
    check-cast p2, Ljava/lang/Iterable;

    .line 124
    .line 125
    invoke-static {p2, p1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 126
    .line 127
    .line 128
    move-result-object p1

    .line 129
    new-instance p2, Lqp0/p;

    .line 130
    .line 131
    invoke-direct {p2, p1}, Lqp0/p;-><init>(Ljava/util/List;)V

    .line 132
    .line 133
    .line 134
    check-cast p0, Lnp0/b;

    .line 135
    .line 136
    iget-object p0, p0, Lnp0/b;->b:Lyy0/c2;

    .line 137
    .line 138
    invoke-virtual {p0, p2}, Lyy0/c2;->j(Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    goto/16 :goto_8

    .line 142
    .line 143
    :cond_7
    invoke-static {p2}, Lmx0/q;->J(Ljava/util/List;)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object p2

    .line 147
    check-cast p2, Llx0/l;

    .line 148
    .line 149
    iget-object p2, p2, Llx0/l;->e:Ljava/lang/Object;

    .line 150
    .line 151
    check-cast p2, Lqp0/b0;

    .line 152
    .line 153
    invoke-static {p1}, Ljp/dg;->b(Lqp0/x;)Lqp0/b0;

    .line 154
    .line 155
    .line 156
    move-result-object p1

    .line 157
    check-cast p0, Lnp0/b;

    .line 158
    .line 159
    const-string v0, "old"

    .line 160
    .line 161
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 162
    .line 163
    .line 164
    iget-object p0, p0, Lnp0/b;->h:Lyy0/c2;

    .line 165
    .line 166
    :cond_8
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 167
    .line 168
    .line 169
    move-result-object v0

    .line 170
    move-object v1, v0

    .line 171
    check-cast v1, Lqp0/g;

    .line 172
    .line 173
    if-eqz v1, :cond_c

    .line 174
    .line 175
    iget-object v3, v1, Lqp0/g;->a:Ljava/util/List;

    .line 176
    .line 177
    check-cast v3, Ljava/util/Collection;

    .line 178
    .line 179
    invoke-static {v3}, Lmx0/q;->z0(Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 180
    .line 181
    .line 182
    move-result-object v3

    .line 183
    invoke-virtual {v3}, Ljava/util/ArrayList;->iterator()Ljava/util/Iterator;

    .line 184
    .line 185
    .line 186
    move-result-object v4

    .line 187
    const/4 v5, 0x0

    .line 188
    :goto_5
    invoke-interface {v4}, Ljava/util/Iterator;->hasNext()Z

    .line 189
    .line 190
    .line 191
    move-result v6

    .line 192
    const/4 v7, -0x1

    .line 193
    if-eqz v6, :cond_a

    .line 194
    .line 195
    invoke-interface {v4}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 196
    .line 197
    .line 198
    move-result-object v6

    .line 199
    check-cast v6, Llx0/l;

    .line 200
    .line 201
    iget-object v6, v6, Llx0/l;->e:Ljava/lang/Object;

    .line 202
    .line 203
    invoke-static {v6, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 204
    .line 205
    .line 206
    move-result v6

    .line 207
    if-eqz v6, :cond_9

    .line 208
    .line 209
    goto :goto_6

    .line 210
    :cond_9
    add-int/lit8 v5, v5, 0x1

    .line 211
    .line 212
    goto :goto_5

    .line 213
    :cond_a
    move v5, v7

    .line 214
    :goto_6
    if-eq v5, v7, :cond_b

    .line 215
    .line 216
    new-instance v4, Ljava/security/SecureRandom;

    .line 217
    .line 218
    invoke-direct {v4}, Ljava/security/SecureRandom;-><init>()V

    .line 219
    .line 220
    .line 221
    invoke-virtual {v4}, Ljava/util/Random;->nextInt()I

    .line 222
    .line 223
    .line 224
    move-result v4

    .line 225
    invoke-static {v4}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 226
    .line 227
    .line 228
    move-result-object v4

    .line 229
    new-instance v6, Llx0/l;

    .line 230
    .line 231
    invoke-direct {v6, v4, p1}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 232
    .line 233
    .line 234
    invoke-virtual {v3, v5, v6}, Ljava/util/ArrayList;->set(ILjava/lang/Object;)Ljava/lang/Object;

    .line 235
    .line 236
    .line 237
    :cond_b
    invoke-static {v3}, Lmx0/q;->x0(Ljava/lang/Iterable;)Ljava/util/List;

    .line 238
    .line 239
    .line 240
    move-result-object v3

    .line 241
    iget-object v4, v1, Lqp0/g;->b:Ljava/lang/Integer;

    .line 242
    .line 243
    iget-boolean v1, v1, Lqp0/g;->c:Z

    .line 244
    .line 245
    new-instance v5, Lqp0/g;

    .line 246
    .line 247
    invoke-direct {v5, v3, v4, v1}, Lqp0/g;-><init>(Ljava/util/List;Ljava/lang/Integer;Z)V

    .line 248
    .line 249
    .line 250
    invoke-static {v5}, Ljp/bg;->e(Lqp0/g;)Lqp0/g;

    .line 251
    .line 252
    .line 253
    move-result-object v1

    .line 254
    goto :goto_7

    .line 255
    :cond_c
    move-object v1, v2

    .line 256
    :goto_7
    invoke-virtual {p0, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 257
    .line 258
    .line 259
    move-result v0

    .line 260
    if-eqz v0, :cond_8

    .line 261
    .line 262
    :cond_d
    :goto_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 263
    .line 264
    return-object p0
.end method
