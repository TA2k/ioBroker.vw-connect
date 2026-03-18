.class public final Lag/u;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Lag/c;

.field public final f:Lag/b;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/l1;

.field public final i:Lyy0/l1;


# direct methods
.method public constructor <init>(Ljava/lang/String;Lag/c;Lag/c;Lag/c;)V
    .locals 1

    .line 1
    const-string p3, "vin"

    .line 2
    .line 3
    invoke-static {p1, p3}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lag/u;->d:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p2, p0, Lag/u;->e:Lag/c;

    .line 12
    .line 13
    sget-object p1, Lag/a;->d:Lag/a;

    .line 14
    .line 15
    sget-object p1, Lag/b;->a:Lag/b;

    .line 16
    .line 17
    iput-object p1, p0, Lag/u;->f:Lag/b;

    .line 18
    .line 19
    sget-object p1, Lag/w;->f:Lag/w;

    .line 20
    .line 21
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    iput-object p1, p0, Lag/u;->g:Lyy0/c2;

    .line 26
    .line 27
    new-instance p2, Lag/r;

    .line 28
    .line 29
    const/4 p3, 0x0

    .line 30
    invoke-direct {p2, p1, p3}, Lag/r;-><init>(Lyy0/c2;I)V

    .line 31
    .line 32
    .line 33
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 34
    .line 35
    .line 36
    move-result-object p3

    .line 37
    new-instance p4, Llc/q;

    .line 38
    .line 39
    sget-object v0, Llc/a;->c:Llc/c;

    .line 40
    .line 41
    invoke-direct {p4, v0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 42
    .line 43
    .line 44
    sget-object v0, Lyy0/u1;->b:Lyy0/w1;

    .line 45
    .line 46
    invoke-static {p2, p3, v0, p4}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 47
    .line 48
    .line 49
    move-result-object p2

    .line 50
    iput-object p2, p0, Lag/u;->h:Lyy0/l1;

    .line 51
    .line 52
    new-instance p2, Lag/r;

    .line 53
    .line 54
    const/4 p3, 0x1

    .line 55
    invoke-direct {p2, p1, p3}, Lag/r;-><init>(Lyy0/c2;I)V

    .line 56
    .line 57
    .line 58
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    sget-object p3, Lag/h;->a:Lag/h;

    .line 63
    .line 64
    invoke-static {p2, p1, v0, p3}, Lyy0/u;->F(Lyy0/i;Lvy0/b0;Lyy0/v1;Ljava/lang/Object;)Lyy0/l1;

    .line 65
    .line 66
    .line 67
    move-result-object p1

    .line 68
    iput-object p1, p0, Lag/u;->i:Lyy0/l1;

    .line 69
    .line 70
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    new-instance p2, La50/a;

    .line 75
    .line 76
    const/4 p3, 0x4

    .line 77
    const/4 p4, 0x0

    .line 78
    invoke-direct {p2, p0, p4, p3}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 79
    .line 80
    .line 81
    const/4 p0, 0x3

    .line 82
    invoke-static {p1, p4, p4, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 83
    .line 84
    .line 85
    return-void
.end method

.method public static final a(Lag/u;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lag/p;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lag/p;

    .line 7
    .line 8
    iget v1, v0, Lag/p;->f:I

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
    iput v1, v0, Lag/p;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lag/p;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lag/p;-><init>(Lag/u;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lag/p;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lag/p;->f:I

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
    goto :goto_3

    .line 52
    :cond_3
    :goto_1
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    :cond_4
    iget-object p1, p0, Lag/u;->g:Lyy0/c2;

    .line 56
    .line 57
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v2

    .line 61
    check-cast v2, Lag/w;

    .line 62
    .line 63
    iget-object v2, v2, Lag/w;->a:Llc/q;

    .line 64
    .line 65
    new-instance v5, Llc/q;

    .line 66
    .line 67
    sget-object v6, Llc/a;->c:Llc/c;

    .line 68
    .line 69
    invoke-direct {v5, v6}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    invoke-static {v2, v5}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 73
    .line 74
    .line 75
    move-result v2

    .line 76
    if-nez v2, :cond_9

    .line 77
    .line 78
    invoke-virtual {p1}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    check-cast p1, Lag/w;

    .line 83
    .line 84
    sget v2, Lag/v;->b:I

    .line 85
    .line 86
    iget-object p1, p1, Lag/w;->b:Ljp/a1;

    .line 87
    .line 88
    instance-of v2, p1, Lag/d;

    .line 89
    .line 90
    if-eqz v2, :cond_5

    .line 91
    .line 92
    check-cast p1, Lag/d;

    .line 93
    .line 94
    iget-object p1, p1, Lag/d;->a:Lag/n;

    .line 95
    .line 96
    sget-object v2, Lag/n;->e:Lag/n;

    .line 97
    .line 98
    if-ne p1, v2, :cond_7

    .line 99
    .line 100
    goto :goto_2

    .line 101
    :cond_5
    instance-of v2, p1, Lag/m;

    .line 102
    .line 103
    if-eqz v2, :cond_6

    .line 104
    .line 105
    check-cast p1, Lag/m;

    .line 106
    .line 107
    iget-object p1, p1, Lag/m;->a:Lag/n;

    .line 108
    .line 109
    sget-object v2, Lag/n;->e:Lag/n;

    .line 110
    .line 111
    if-ne p1, v2, :cond_7

    .line 112
    .line 113
    goto :goto_2

    .line 114
    :cond_6
    instance-of p0, p1, Lag/f;

    .line 115
    .line 116
    if-eqz p0, :cond_8

    .line 117
    .line 118
    :cond_7
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 119
    .line 120
    return-object p0

    .line 121
    :cond_8
    new-instance p0, La8/r0;

    .line 122
    .line 123
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 124
    .line 125
    .line 126
    throw p0

    .line 127
    :cond_9
    :goto_2
    sget-wide v5, Lag/v;->a:J

    .line 128
    .line 129
    iput v4, v0, Lag/p;->f:I

    .line 130
    .line 131
    invoke-static {v5, v6, v0}, Lvy0/e0;->q(JLkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    if-ne p1, v1, :cond_a

    .line 136
    .line 137
    goto :goto_4

    .line 138
    :cond_a
    :goto_3
    iput v3, v0, Lag/p;->f:I

    .line 139
    .line 140
    invoke-virtual {p0, v0}, Lag/u;->b(Lrx0/c;)Ljava/lang/Object;

    .line 141
    .line 142
    .line 143
    move-result-object p1

    .line 144
    if-ne p1, v1, :cond_4

    .line 145
    .line 146
    :goto_4
    return-object v1
.end method


# virtual methods
.method public final b(Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    instance-of v0, p1, Lag/o;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lag/o;

    .line 7
    .line 8
    iget v1, v0, Lag/o;->f:I

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
    iput v1, v0, Lag/o;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lag/o;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lag/o;-><init>(Lag/u;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lag/o;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lag/o;->f:I

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
    sget-object p1, Lag/a;->d:Lag/a;

    .line 52
    .line 53
    iput v3, v0, Lag/o;->f:I

    .line 54
    .line 55
    iget-object p1, p0, Lag/u;->e:Lag/c;

    .line 56
    .line 57
    iget-object v2, p0, Lag/u;->d:Ljava/lang/String;

    .line 58
    .line 59
    invoke-virtual {p1, v2, v0}, Lag/c;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p1

    .line 63
    if-ne p1, v1, :cond_3

    .line 64
    .line 65
    return-object v1

    .line 66
    :cond_3
    :goto_1
    check-cast p1, Llx0/o;

    .line 67
    .line 68
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 69
    .line 70
    instance-of v0, p1, Llx0/n;

    .line 71
    .line 72
    if-nez v0, :cond_11

    .line 73
    .line 74
    move-object v0, p1

    .line 75
    check-cast v0, Lxf/p;

    .line 76
    .line 77
    iget-object v1, p0, Lag/u;->f:Lag/b;

    .line 78
    .line 79
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 80
    .line 81
    .line 82
    const-string v1, "response"

    .line 83
    .line 84
    invoke-static {v0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 85
    .line 86
    .line 87
    new-instance v2, Lag/w;

    .line 88
    .line 89
    new-instance v3, Llc/q;

    .line 90
    .line 91
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 92
    .line 93
    invoke-direct {v3, v1}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 94
    .line 95
    .line 96
    instance-of v1, v0, Lxf/g;

    .line 97
    .line 98
    const/4 v4, 0x1

    .line 99
    if-eqz v1, :cond_6

    .line 100
    .line 101
    move-object v1, v0

    .line 102
    check-cast v1, Lxf/g;

    .line 103
    .line 104
    new-instance v5, Lag/d;

    .line 105
    .line 106
    iget-object v1, v1, Lxf/g;->b:Lxf/f;

    .line 107
    .line 108
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 109
    .line 110
    .line 111
    move-result v1

    .line 112
    if-eqz v1, :cond_5

    .line 113
    .line 114
    if-ne v1, v4, :cond_4

    .line 115
    .line 116
    sget-object v1, Lag/n;->e:Lag/n;

    .line 117
    .line 118
    goto :goto_2

    .line 119
    :cond_4
    new-instance p0, La8/r0;

    .line 120
    .line 121
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 122
    .line 123
    .line 124
    throw p0

    .line 125
    :cond_5
    sget-object v1, Lag/n;->d:Lag/n;

    .line 126
    .line 127
    :goto_2
    sget-object v6, Lag/l;->d:Lag/l;

    .line 128
    .line 129
    invoke-direct {v5, v1, v6}, Lag/d;-><init>(Lag/n;Lag/l;)V

    .line 130
    .line 131
    .line 132
    goto :goto_4

    .line 133
    :cond_6
    instance-of v1, v0, Lxf/l;

    .line 134
    .line 135
    if-eqz v1, :cond_a

    .line 136
    .line 137
    move-object v1, v0

    .line 138
    check-cast v1, Lxf/l;

    .line 139
    .line 140
    new-instance v5, Lag/f;

    .line 141
    .line 142
    iget-object v1, v1, Lxf/l;->b:Lxf/j;

    .line 143
    .line 144
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    .line 145
    .line 146
    .line 147
    move-result v1

    .line 148
    if-eqz v1, :cond_9

    .line 149
    .line 150
    if-eq v1, v4, :cond_8

    .line 151
    .line 152
    const/4 v6, 0x2

    .line 153
    if-ne v1, v6, :cond_7

    .line 154
    .line 155
    sget-object v1, Lag/e;->e:Lag/e;

    .line 156
    .line 157
    goto :goto_3

    .line 158
    :cond_7
    new-instance p0, La8/r0;

    .line 159
    .line 160
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 161
    .line 162
    .line 163
    throw p0

    .line 164
    :cond_8
    sget-object v1, Lag/e;->e:Lag/e;

    .line 165
    .line 166
    goto :goto_3

    .line 167
    :cond_9
    sget-object v1, Lag/e;->d:Lag/e;

    .line 168
    .line 169
    :goto_3
    sget-object v6, Lag/l;->d:Lag/l;

    .line 170
    .line 171
    invoke-direct {v5, v1, v6}, Lag/f;-><init>(Lag/e;Lag/l;)V

    .line 172
    .line 173
    .line 174
    goto :goto_4

    .line 175
    :cond_a
    instance-of v1, v0, Lxf/o;

    .line 176
    .line 177
    if-eqz v1, :cond_10

    .line 178
    .line 179
    move-object v1, v0

    .line 180
    check-cast v1, Lxf/o;

    .line 181
    .line 182
    new-instance v5, Lag/m;

    .line 183
    .line 184
    sget-object v6, Lag/n;->d:Lag/n;

    .line 185
    .line 186
    iget-object v1, v1, Lxf/o;->b:Ljava/lang/String;

    .line 187
    .line 188
    sget-object v7, Lag/l;->d:Lag/l;

    .line 189
    .line 190
    invoke-direct {v5, v6, v1, v7}, Lag/m;-><init>(Lag/n;Ljava/lang/String;Lag/l;)V

    .line 191
    .line 192
    .line 193
    :goto_4
    instance-of v1, v0, Lxf/l;

    .line 194
    .line 195
    const/4 v6, 0x0

    .line 196
    if-eqz v1, :cond_b

    .line 197
    .line 198
    move-object v7, v0

    .line 199
    check-cast v7, Lxf/l;

    .line 200
    .line 201
    goto :goto_5

    .line 202
    :cond_b
    move-object v7, v6

    .line 203
    :goto_5
    if-eqz v7, :cond_c

    .line 204
    .line 205
    iget-object v7, v7, Lxf/l;->b:Lxf/j;

    .line 206
    .line 207
    goto :goto_6

    .line 208
    :cond_c
    move-object v7, v6

    .line 209
    :goto_6
    sget-object v8, Lxf/j;->e:Lxf/j;

    .line 210
    .line 211
    if-ne v7, v8, :cond_d

    .line 212
    .line 213
    goto :goto_7

    .line 214
    :cond_d
    const/4 v4, 0x0

    .line 215
    :goto_7
    if-eqz v1, :cond_e

    .line 216
    .line 217
    check-cast v0, Lxf/l;

    .line 218
    .line 219
    goto :goto_8

    .line 220
    :cond_e
    move-object v0, v6

    .line 221
    :goto_8
    if-eqz v0, :cond_f

    .line 222
    .line 223
    iget-object v6, v0, Lxf/l;->c:Ljava/lang/String;

    .line 224
    .line 225
    :cond_f
    sget-object v7, Lag/h;->a:Lag/h;

    .line 226
    .line 227
    move-object v9, v5

    .line 228
    move v5, v4

    .line 229
    move-object v4, v9

    .line 230
    invoke-direct/range {v2 .. v7}, Lag/w;-><init>(Llc/q;Ljp/a1;ZLjava/lang/String;Lag/k;)V

    .line 231
    .line 232
    .line 233
    iget-object v0, p0, Lag/u;->g:Lyy0/c2;

    .line 234
    .line 235
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 236
    .line 237
    .line 238
    const/4 v1, 0x0

    .line 239
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->k(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 240
    .line 241
    .line 242
    goto :goto_9

    .line 243
    :cond_10
    new-instance p0, La8/r0;

    .line 244
    .line 245
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 246
    .line 247
    .line 248
    throw p0

    .line 249
    :cond_11
    :goto_9
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 250
    .line 251
    .line 252
    move-result-object p1

    .line 253
    if-eqz p1, :cond_13

    .line 254
    .line 255
    :cond_12
    iget-object v0, p0, Lag/u;->g:Lyy0/c2;

    .line 256
    .line 257
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 258
    .line 259
    .line 260
    move-result-object v1

    .line 261
    move-object v2, v1

    .line 262
    check-cast v2, Lag/w;

    .line 263
    .line 264
    invoke-static {p1}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 265
    .line 266
    .line 267
    move-result-object v3

    .line 268
    new-instance v4, Llc/q;

    .line 269
    .line 270
    invoke-direct {v4, v3}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 271
    .line 272
    .line 273
    const/16 v3, 0x1e

    .line 274
    .line 275
    const/4 v5, 0x0

    .line 276
    invoke-static {v2, v4, v5, v5, v3}, Lag/w;->a(Lag/w;Llc/q;Ljp/a1;Lag/k;I)Lag/w;

    .line 277
    .line 278
    .line 279
    move-result-object v2

    .line 280
    invoke-virtual {v0, v1, v2}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 281
    .line 282
    .line 283
    move-result v0

    .line 284
    if-eqz v0, :cond_12

    .line 285
    .line 286
    :cond_13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 287
    .line 288
    return-object p0
.end method
