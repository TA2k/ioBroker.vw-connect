.class public final Lvh/y;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lci/a;

.field public final e:Lyy0/c2;

.field public final f:Lyy0/l1;

.field public g:Lai/a;

.field public final h:Lyy0/q1;

.field public final i:Lyy0/k1;


# direct methods
.method public constructor <init>(Lzg/c1;Lai/b;Lci/a;)V
    .locals 8

    .line 1
    new-instance v0, Lvh/w;

    .line 2
    .line 3
    new-instance v5, Lvh/v;

    .line 4
    .line 5
    sget-object v1, Lvh/v;->e:Lzg/f1;

    .line 6
    .line 7
    const/4 v7, 0x0

    .line 8
    invoke-direct {v5, p1, v7, v7, v1}, Lvh/v;-><init>(Lzg/c1;Ljava/lang/Integer;Ljava/lang/Integer;Lzg/f1;)V

    .line 9
    .line 10
    .line 11
    new-instance v6, Lvh/u;

    .line 12
    .line 13
    invoke-direct {v6}, Lvh/u;-><init>()V

    .line 14
    .line 15
    .line 16
    const/4 v1, 0x0

    .line 17
    const/4 v2, 0x0

    .line 18
    const/4 v3, 0x0

    .line 19
    const/4 v4, 0x0

    .line 20
    invoke-direct/range {v0 .. v6}, Lvh/w;-><init>(IZZZLvh/v;Lvh/u;)V

    .line 21
    .line 22
    .line 23
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 24
    .line 25
    .line 26
    iput-object p3, p0, Lvh/y;->d:Lci/a;

    .line 27
    .line 28
    invoke-static {v0}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iput-object p1, p0, Lvh/y;->e:Lyy0/c2;

    .line 33
    .line 34
    new-instance p3, Lyy0/l1;

    .line 35
    .line 36
    invoke-direct {p3, p1}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 37
    .line 38
    .line 39
    iput-object p3, p0, Lvh/y;->f:Lyy0/l1;

    .line 40
    .line 41
    new-instance p1, Lai/a;

    .line 42
    .line 43
    invoke-direct {p1, v7, p2}, Lai/a;-><init>(Lzg/h1;Lai/b;)V

    .line 44
    .line 45
    .line 46
    iput-object p1, p0, Lvh/y;->g:Lai/a;

    .line 47
    .line 48
    const/4 p1, 0x7

    .line 49
    const/4 p2, 0x0

    .line 50
    invoke-static {p2, p1, v7}, Lyy0/u;->b(IILxy0/a;)Lyy0/q1;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    iput-object p1, p0, Lvh/y;->h:Lyy0/q1;

    .line 55
    .line 56
    new-instance p2, Lyy0/k1;

    .line 57
    .line 58
    invoke-direct {p2, p1}, Lyy0/k1;-><init>(Lyy0/n1;)V

    .line 59
    .line 60
    .line 61
    iput-object p2, p0, Lvh/y;->i:Lyy0/k1;

    .line 62
    .line 63
    return-void
.end method

.method public static d(Lyy0/c2;Z)V
    .locals 9

    .line 1
    :cond_0
    invoke-virtual {p0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    move-object v1, v0

    .line 6
    check-cast v1, Lvh/w;

    .line 7
    .line 8
    iget-object v2, v1, Lvh/w;->f:Lvh/u;

    .line 9
    .line 10
    iget-object v2, v2, Lvh/u;->b:Llc/l;

    .line 11
    .line 12
    new-instance v7, Lvh/u;

    .line 13
    .line 14
    invoke-direct {v7, p1, v2}, Lvh/u;-><init>(ZLlc/l;)V

    .line 15
    .line 16
    .line 17
    const/16 v8, 0x3f

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    const/4 v3, 0x0

    .line 21
    const/4 v4, 0x0

    .line 22
    const/4 v5, 0x0

    .line 23
    const/4 v6, 0x0

    .line 24
    invoke-static/range {v1 .. v8}, Lvh/w;->a(Lvh/w;IZZZLvh/v;Lvh/u;I)Lvh/w;

    .line 25
    .line 26
    .line 27
    move-result-object v1

    .line 28
    invoke-virtual {p0, v0, v1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result v0

    .line 32
    if-eqz v0, :cond_0

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final a(Lrx0/c;)Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Lvh/y;->e:Lyy0/c2;

    .line 2
    .line 3
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Lvh/w;

    .line 8
    .line 9
    iget v0, v0, Lvh/w;->a:I

    .line 10
    .line 11
    add-int/lit8 v0, v0, 0x1

    .line 12
    .line 13
    sget-object v1, Lvh/a;->k:Lsx0/b;

    .line 14
    .line 15
    invoke-static {v0, v1}, Lmx0/q;->M(ILjava/util/List;)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    check-cast v0, Lvh/a;

    .line 20
    .line 21
    if-nez v0, :cond_0

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v1, Lvh/d;

    .line 25
    .line 26
    invoke-direct {v1, v0}, Lvh/d;-><init>(Lvh/a;)V

    .line 27
    .line 28
    .line 29
    iget-object p0, p0, Lvh/y;->h:Lyy0/q1;

    .line 30
    .line 31
    invoke-virtual {p0, v1, p1}, Lyy0/q1;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 32
    .line 33
    .line 34
    move-result-object p0

    .line 35
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    if-ne p0, p1, :cond_1

    .line 38
    .line 39
    return-object p0

    .line 40
    :cond_1
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 41
    .line 42
    return-object p0
.end method

.method public final b(Lvh/t;)V
    .locals 4

    .line 1
    const-string v0, "event"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    new-instance v1, Ltz/o2;

    .line 11
    .line 12
    const/16 v2, 0x19

    .line 13
    .line 14
    const/4 v3, 0x0

    .line 15
    invoke-direct {v1, v2, p1, p0, v3}, Ltz/o2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 16
    .line 17
    .line 18
    const/4 p0, 0x3

    .line 19
    invoke-static {v0, v3, v3, v1, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 20
    .line 21
    .line 22
    return-void
.end method

.method public final f(Lrx0/c;)Ljava/lang/Object;
    .locals 14

    .line 1
    instance-of v0, p1, Lvh/x;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lvh/x;

    .line 7
    .line 8
    iget v1, v0, Lvh/x;->h:I

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
    iput v1, v0, Lvh/x;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lvh/x;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lvh/x;-><init>(Lvh/y;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lvh/x;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lvh/x;->h:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x0

    .line 33
    iget-object v5, p0, Lvh/y;->e:Lyy0/c2;

    .line 34
    .line 35
    const/4 v6, 0x1

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v6, :cond_2

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    iget-object v1, v0, Lvh/x;->e:Lzg/h1;

    .line 43
    .line 44
    iget-object v0, v0, Lvh/x;->d:Ljava/lang/Object;

    .line 45
    .line 46
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 47
    .line 48
    .line 49
    goto :goto_3

    .line 50
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 51
    .line 52
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 53
    .line 54
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 55
    .line 56
    .line 57
    throw p0

    .line 58
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    invoke-virtual {v5}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    check-cast p1, Lvh/w;

    .line 70
    .line 71
    iget-object p1, p1, Lvh/w;->e:Lvh/v;

    .line 72
    .line 73
    new-instance v2, Lbh/t;

    .line 74
    .line 75
    iget-object v7, p1, Lvh/v;->b:Ljava/lang/Integer;

    .line 76
    .line 77
    const-string v8, "Required value was null."

    .line 78
    .line 79
    if-eqz v7, :cond_a

    .line 80
    .line 81
    invoke-virtual {v7}, Ljava/lang/Number;->intValue()I

    .line 82
    .line 83
    .line 84
    move-result v7

    .line 85
    iget-object v9, p1, Lvh/v;->a:Lzg/c1;

    .line 86
    .line 87
    iget-object v9, v9, Lzg/c1;->a:Ljava/lang/String;

    .line 88
    .line 89
    iget-object v10, p1, Lvh/v;->c:Ljava/lang/Integer;

    .line 90
    .line 91
    if-eqz v10, :cond_9

    .line 92
    .line 93
    invoke-virtual {v10}, Ljava/lang/Number;->intValue()I

    .line 94
    .line 95
    .line 96
    move-result v8

    .line 97
    iget-object p1, p1, Lvh/v;->d:Lzg/f1;

    .line 98
    .line 99
    invoke-direct {v2, v7, v9, v8, p1}, Lbh/t;-><init>(ILjava/lang/String;ILzg/f1;)V

    .line 100
    .line 101
    .line 102
    invoke-static {v5, v6}, Lvh/y;->d(Lyy0/c2;Z)V

    .line 103
    .line 104
    .line 105
    iput v6, v0, Lvh/x;->h:I

    .line 106
    .line 107
    iget-object p1, p0, Lvh/y;->d:Lci/a;

    .line 108
    .line 109
    invoke-virtual {p1, v2, v0}, Lci/a;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 110
    .line 111
    .line 112
    move-result-object p1

    .line 113
    if-ne p1, v1, :cond_4

    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_4
    :goto_1
    check-cast p1, Llx0/o;

    .line 117
    .line 118
    iget-object p1, p1, Llx0/o;->d:Ljava/lang/Object;

    .line 119
    .line 120
    instance-of v2, p1, Llx0/n;

    .line 121
    .line 122
    if-nez v2, :cond_6

    .line 123
    .line 124
    move-object v2, p1

    .line 125
    check-cast v2, Lzg/h1;

    .line 126
    .line 127
    iput-object p1, v0, Lvh/x;->d:Ljava/lang/Object;

    .line 128
    .line 129
    iput-object v2, v0, Lvh/x;->e:Lzg/h1;

    .line 130
    .line 131
    iput v3, v0, Lvh/x;->h:I

    .line 132
    .line 133
    invoke-virtual {p0, v0}, Lvh/y;->a(Lrx0/c;)Ljava/lang/Object;

    .line 134
    .line 135
    .line 136
    move-result-object v0

    .line 137
    if-ne v0, v1, :cond_5

    .line 138
    .line 139
    :goto_2
    return-object v1

    .line 140
    :cond_5
    move-object v0, p1

    .line 141
    move-object v1, v2

    .line 142
    :goto_3
    iget-object p1, p0, Lvh/y;->g:Lai/a;

    .line 143
    .line 144
    iget-object p1, p1, Lai/a;->b:Lai/b;

    .line 145
    .line 146
    new-instance v2, Lai/a;

    .line 147
    .line 148
    invoke-direct {v2, v1, p1}, Lai/a;-><init>(Lzg/h1;Lai/b;)V

    .line 149
    .line 150
    .line 151
    iput-object v2, p0, Lvh/y;->g:Lai/a;

    .line 152
    .line 153
    invoke-static {v5, v4}, Lvh/y;->d(Lyy0/c2;Z)V

    .line 154
    .line 155
    .line 156
    move-object p1, v0

    .line 157
    :cond_6
    invoke-static {p1}, Llx0/o;->a(Ljava/lang/Object;)Ljava/lang/Throwable;

    .line 158
    .line 159
    .line 160
    move-result-object p0

    .line 161
    if-eqz p0, :cond_8

    .line 162
    .line 163
    :cond_7
    invoke-virtual {v5}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 164
    .line 165
    .line 166
    move-result-object p1

    .line 167
    move-object v6, p1

    .line 168
    check-cast v6, Lvh/w;

    .line 169
    .line 170
    iget-object v0, v6, Lvh/w;->f:Lvh/u;

    .line 171
    .line 172
    invoke-static {p0}, Llc/c;->b(Ljava/lang/Throwable;)Llc/l;

    .line 173
    .line 174
    .line 175
    move-result-object v1

    .line 176
    iget-boolean v0, v0, Lvh/u;->a:Z

    .line 177
    .line 178
    new-instance v12, Lvh/u;

    .line 179
    .line 180
    invoke-direct {v12, v0, v1}, Lvh/u;-><init>(ZLlc/l;)V

    .line 181
    .line 182
    .line 183
    const/16 v13, 0x3f

    .line 184
    .line 185
    const/4 v7, 0x0

    .line 186
    const/4 v8, 0x0

    .line 187
    const/4 v9, 0x0

    .line 188
    const/4 v10, 0x0

    .line 189
    const/4 v11, 0x0

    .line 190
    invoke-static/range {v6 .. v13}, Lvh/w;->a(Lvh/w;IZZZLvh/v;Lvh/u;I)Lvh/w;

    .line 191
    .line 192
    .line 193
    move-result-object v0

    .line 194
    invoke-virtual {v5, p1, v0}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result p1

    .line 198
    if-eqz p1, :cond_7

    .line 199
    .line 200
    invoke-static {v5, v4}, Lvh/y;->d(Lyy0/c2;Z)V

    .line 201
    .line 202
    .line 203
    :cond_8
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 204
    .line 205
    return-object p0

    .line 206
    :cond_9
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 207
    .line 208
    invoke-direct {p0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 209
    .line 210
    .line 211
    throw p0

    .line 212
    :cond_a
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 213
    .line 214
    invoke-direct {p0, v8}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 215
    .line 216
    .line 217
    throw p0
.end method
