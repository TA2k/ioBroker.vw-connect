.class public final Lhv0/f0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lnn0/t;

.field public final b:Lhv0/t;

.field public final c:Lal0/x0;

.field public final d:Lml0/i;

.field public final e:Lfg0/d;

.field public final f:Lwj0/j0;


# direct methods
.method public constructor <init>(Lnn0/t;Lhv0/t;Lal0/x0;Lml0/i;Lfg0/d;Lwj0/j0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhv0/f0;->a:Lnn0/t;

    .line 5
    .line 6
    iput-object p2, p0, Lhv0/f0;->b:Lhv0/t;

    .line 7
    .line 8
    iput-object p3, p0, Lhv0/f0;->c:Lal0/x0;

    .line 9
    .line 10
    iput-object p4, p0, Lhv0/f0;->d:Lml0/i;

    .line 11
    .line 12
    iput-object p5, p0, Lhv0/f0;->e:Lfg0/d;

    .line 13
    .line 14
    iput-object p6, p0, Lhv0/f0;->f:Lwj0/j0;

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lhv0/f0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    instance-of v0, p1, Lhv0/d0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lhv0/d0;

    .line 7
    .line 8
    iget v1, v0, Lhv0/d0;->f:I

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
    iput v1, v0, Lhv0/d0;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lhv0/d0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lhv0/d0;-><init>(Lhv0/f0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lhv0/d0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lhv0/d0;->f:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v2, :cond_3

    .line 36
    .line 37
    if-eq v2, v5, :cond_2

    .line 38
    .line 39
    if-ne v2, v4, :cond_1

    .line 40
    .line 41
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    return-object v3

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 54
    .line 55
    .line 56
    goto :goto_1

    .line 57
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    iget-object p1, p0, Lhv0/f0;->b:Lhv0/t;

    .line 61
    .line 62
    invoke-virtual {p1}, Lhv0/t;->invoke()Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object p1

    .line 66
    check-cast p1, Lyy0/i;

    .line 67
    .line 68
    iput v5, v0, Lhv0/d0;->f:I

    .line 69
    .line 70
    invoke-static {p1, v0}, Lyy0/u;->w(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    if-ne p1, v1, :cond_4

    .line 75
    .line 76
    goto/16 :goto_2

    .line 77
    .line 78
    :cond_4
    :goto_1
    check-cast p1, Liv0/f;

    .line 79
    .line 80
    instance-of p1, p1, Liv0/n;

    .line 81
    .line 82
    if-eqz p1, :cond_5

    .line 83
    .line 84
    goto/16 :goto_3

    .line 85
    .line 86
    :cond_5
    iget-object p1, p0, Lhv0/f0;->d:Lml0/i;

    .line 87
    .line 88
    invoke-virtual {p1}, Lml0/i;->invoke()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object p1

    .line 92
    check-cast p1, Lyy0/i;

    .line 93
    .line 94
    invoke-static {p1}, Lbb/j0;->i(Lyy0/i;)Lyy0/m1;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    new-instance v2, Lh70/f;

    .line 99
    .line 100
    const/4 v6, 0x7

    .line 101
    invoke-direct {v2, v6}, Lh70/f;-><init>(I)V

    .line 102
    .line 103
    .line 104
    invoke-static {p1, v2}, Lbb/j0;->b(Lyy0/i;Lay0/k;)Lne0/k;

    .line 105
    .line 106
    .line 107
    move-result-object p1

    .line 108
    new-instance v2, Lam0/i;

    .line 109
    .line 110
    const/16 v6, 0x8

    .line 111
    .line 112
    invoke-direct {v2, p1, v6}, Lam0/i;-><init>(Ljava/lang/Object;I)V

    .line 113
    .line 114
    .line 115
    new-instance p1, Lal0/m0;

    .line 116
    .line 117
    const/4 v7, 0x0

    .line 118
    const/16 v8, 0xd

    .line 119
    .line 120
    invoke-direct {p1, v4, v7, v8}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 121
    .line 122
    .line 123
    new-instance v9, Lne0/n;

    .line 124
    .line 125
    invoke-direct {v9, p1, v2}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 126
    .line 127
    .line 128
    iget-object p1, p0, Lhv0/f0;->e:Lfg0/d;

    .line 129
    .line 130
    invoke-virtual {p1}, Lfg0/d;->invoke()Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object p1

    .line 134
    check-cast p1, Lyy0/i;

    .line 135
    .line 136
    new-instance v2, Lac/l;

    .line 137
    .line 138
    invoke-direct {v2, v8, p1, p0}, Lac/l;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 139
    .line 140
    .line 141
    new-instance p1, Lh60/b;

    .line 142
    .line 143
    const/16 v8, 0xb

    .line 144
    .line 145
    invoke-direct {p1, v8}, Lh60/b;-><init>(I)V

    .line 146
    .line 147
    .line 148
    invoke-static {v4, p1}, Lkotlin/jvm/internal/j0;->e(ILjava/lang/Object;)V

    .line 149
    .line 150
    .line 151
    new-instance v8, Lyy0/g;

    .line 152
    .line 153
    invoke-direct {v8, p1, v2}, Lyy0/g;-><init>(Lay0/n;Lyy0/i;)V

    .line 154
    .line 155
    .line 156
    new-instance p1, Lal0/y0;

    .line 157
    .line 158
    const/4 v2, 0x3

    .line 159
    invoke-direct {p1, v2, v7, v6}, Lal0/y0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 160
    .line 161
    .line 162
    new-instance v6, Lbn0/f;

    .line 163
    .line 164
    const/4 v10, 0x5

    .line 165
    invoke-direct {v6, v9, v8, p1, v10}, Lbn0/f;-><init>(Lyy0/i;Ljava/lang/Object;Ljava/lang/Object;I)V

    .line 166
    .line 167
    .line 168
    sget p1, Lmy0/c;->g:I

    .line 169
    .line 170
    sget-object p1, Lmy0/e;->h:Lmy0/e;

    .line 171
    .line 172
    invoke-static {v5, p1}, Lmy0/h;->s(ILmy0/e;)J

    .line 173
    .line 174
    .line 175
    move-result-wide v8

    .line 176
    invoke-static {v8, v9}, Lvy0/e0;->O(J)J

    .line 177
    .line 178
    .line 179
    move-result-wide v8

    .line 180
    invoke-static {v6, v8, v9}, Lyy0/u;->o(Lyy0/i;J)Lyy0/i;

    .line 181
    .line 182
    .line 183
    move-result-object v6

    .line 184
    const/4 v8, 0x4

    .line 185
    invoke-static {v8, p1}, Lmy0/h;->s(ILmy0/e;)J

    .line 186
    .line 187
    .line 188
    move-result-wide v9

    .line 189
    new-instance p1, Lyy0/t;

    .line 190
    .line 191
    invoke-direct {p1, v9, v10, v6, v7}, Lyy0/t;-><init>(JLyy0/i;Lkotlin/coroutines/Continuation;)V

    .line 192
    .line 193
    .line 194
    new-instance v6, Lyy0/m1;

    .line 195
    .line 196
    invoke-direct {v6, p1}, Lyy0/m1;-><init>(Lay0/o;)V

    .line 197
    .line 198
    .line 199
    iget-object p1, p0, Lhv0/f0;->c:Lal0/x0;

    .line 200
    .line 201
    invoke-virtual {p1}, Lal0/x0;->invoke()Ljava/lang/Object;

    .line 202
    .line 203
    .line 204
    move-result-object p1

    .line 205
    check-cast p1, Lyy0/i;

    .line 206
    .line 207
    invoke-static {p1, v5}, Lyy0/u;->G(Lyy0/i;I)Lyy0/d0;

    .line 208
    .line 209
    .line 210
    move-result-object p1

    .line 211
    new-instance v5, Lac/k;

    .line 212
    .line 213
    const/16 v9, 0xe

    .line 214
    .line 215
    invoke-direct {v5, v9, p0, v6, v7}, Lac/k;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 216
    .line 217
    .line 218
    invoke-static {p1, v5}, Lyy0/u;->H(Lyy0/i;Lay0/o;)Lzy0/j;

    .line 219
    .line 220
    .line 221
    move-result-object p1

    .line 222
    new-instance v5, Lal0/j0;

    .line 223
    .line 224
    invoke-direct {v5, p1, v8}, Lal0/j0;-><init>(Lzy0/j;I)V

    .line 225
    .line 226
    .line 227
    invoke-static {v5}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 228
    .line 229
    .line 230
    move-result-object p1

    .line 231
    new-instance v5, Lg1/e1;

    .line 232
    .line 233
    invoke-direct {v5, v2, v7, v2}, Lg1/e1;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 234
    .line 235
    .line 236
    new-instance v2, Lne0/n;

    .line 237
    .line 238
    invoke-direct {v2, p1, v5}, Lne0/n;-><init>(Lyy0/i;Lay0/o;)V

    .line 239
    .line 240
    .line 241
    new-instance p1, Lgt0/c;

    .line 242
    .line 243
    const/16 v5, 0xf

    .line 244
    .line 245
    invoke-direct {p1, p0, v5}, Lgt0/c;-><init>(Ljava/lang/Object;I)V

    .line 246
    .line 247
    .line 248
    iput v4, v0, Lhv0/d0;->f:I

    .line 249
    .line 250
    invoke-virtual {v2, p1, v0}, Lne0/n;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 251
    .line 252
    .line 253
    move-result-object p0

    .line 254
    if-ne p0, v1, :cond_6

    .line 255
    .line 256
    :goto_2
    return-object v1

    .line 257
    :cond_6
    :goto_3
    return-object v3
.end method
