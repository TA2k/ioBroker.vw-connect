.class public final Luo0/q;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lgb0/f;

.field public final i:Lkf0/o;

.field public final j:Lro0/p;

.field public final k:Lro0/f;

.field public final l:Ltr0/b;

.field public final m:Lij0/a;


# direct methods
.method public constructor <init>(Lro0/m;Lgb0/f;Lkf0/o;Lro0/p;Lro0/f;Ltr0/b;Lij0/a;)V
    .locals 2

    .line 1
    new-instance v0, Luo0/o;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1, v1}, Luo0/o;-><init>(Lql0/g;Llp/v1;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p2, p0, Luo0/q;->h:Lgb0/f;

    .line 11
    .line 12
    iput-object p3, p0, Luo0/q;->i:Lkf0/o;

    .line 13
    .line 14
    iput-object p4, p0, Luo0/q;->j:Lro0/p;

    .line 15
    .line 16
    iput-object p5, p0, Luo0/q;->k:Lro0/f;

    .line 17
    .line 18
    iput-object p6, p0, Luo0/q;->l:Ltr0/b;

    .line 19
    .line 20
    iput-object p7, p0, Luo0/q;->m:Lij0/a;

    .line 21
    .line 22
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 23
    .line 24
    .line 25
    move-result-object p2

    .line 26
    new-instance p3, Ltz/o2;

    .line 27
    .line 28
    const/16 p4, 0x10

    .line 29
    .line 30
    invoke-direct {p3, p4, p1, p0, v1}, Ltz/o2;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 31
    .line 32
    .line 33
    const/4 p0, 0x3

    .line 34
    invoke-static {p2, v1, v1, p3, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 35
    .line 36
    .line 37
    return-void
.end method

.method public static final h(Luo0/q;Lto0/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 11

    .line 1
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 2
    .line 3
    instance-of v0, p2, Luo0/p;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    move-object v0, p2

    .line 8
    check-cast v0, Luo0/p;

    .line 9
    .line 10
    iget v2, v0, Luo0/p;->h:I

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
    iput v2, v0, Luo0/p;->h:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v0, Luo0/p;

    .line 23
    .line 24
    invoke-direct {v0, p0, p2}, Luo0/p;-><init>(Luo0/q;Lkotlin/coroutines/Continuation;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p2, v0, Luo0/p;->f:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v0, Luo0/p;->h:I

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, 0x1

    .line 35
    if-eqz v3, :cond_3

    .line 36
    .line 37
    if-eq v3, v5, :cond_2

    .line 38
    .line 39
    if-ne v3, v4, :cond_1

    .line 40
    .line 41
    iget-object p1, v0, Luo0/p;->e:Lss0/b;

    .line 42
    .line 43
    iget-object v0, v0, Luo0/p;->d:Lto0/l;

    .line 44
    .line 45
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_3

    .line 49
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 50
    .line 51
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 52
    .line 53
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 54
    .line 55
    .line 56
    throw p0

    .line 57
    :cond_2
    iget-object p1, v0, Luo0/p;->d:Lto0/l;

    .line 58
    .line 59
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    iget-object p2, p0, Luo0/q;->h:Lgb0/f;

    .line 67
    .line 68
    iput-object p1, v0, Luo0/p;->d:Lto0/l;

    .line 69
    .line 70
    iput v5, v0, Luo0/p;->h:I

    .line 71
    .line 72
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 73
    .line 74
    .line 75
    invoke-virtual {p2, v0}, Lgb0/f;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p2

    .line 79
    if-ne p2, v2, :cond_4

    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_4
    :goto_1
    check-cast p2, Lss0/b;

    .line 83
    .line 84
    iget-object v3, p0, Luo0/q;->i:Lkf0/o;

    .line 85
    .line 86
    iput-object p1, v0, Luo0/p;->d:Lto0/l;

    .line 87
    .line 88
    iput-object p2, v0, Luo0/p;->e:Lss0/b;

    .line 89
    .line 90
    iput v4, v0, Luo0/p;->h:I

    .line 91
    .line 92
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 93
    .line 94
    .line 95
    invoke-virtual {v3, v0}, Lkf0/o;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 96
    .line 97
    .line 98
    move-result-object v0

    .line 99
    if-ne v0, v2, :cond_5

    .line 100
    .line 101
    :goto_2
    return-object v2

    .line 102
    :cond_5
    move-object v10, v0

    .line 103
    move-object v0, p1

    .line 104
    move-object p1, p2

    .line 105
    move-object p2, v10

    .line 106
    :goto_3
    check-cast p2, Lne0/t;

    .line 107
    .line 108
    instance-of v2, p2, Lne0/c;

    .line 109
    .line 110
    const/4 v3, 0x0

    .line 111
    if-eqz v2, :cond_7

    .line 112
    .line 113
    :cond_6
    move-object p2, v3

    .line 114
    goto :goto_4

    .line 115
    :cond_7
    instance-of v2, p2, Lne0/e;

    .line 116
    .line 117
    if-eqz v2, :cond_9

    .line 118
    .line 119
    check-cast p2, Lne0/e;

    .line 120
    .line 121
    iget-object p2, p2, Lne0/e;->a:Ljava/lang/Object;

    .line 122
    .line 123
    check-cast p2, Lss0/j0;

    .line 124
    .line 125
    iget-object p2, p2, Lss0/j0;->d:Ljava/lang/String;

    .line 126
    .line 127
    sget-object v2, Lss0/e;->v1:Lss0/e;

    .line 128
    .line 129
    invoke-static {p1, v2}, Llp/pf;->c(Lss0/b;Lss0/e;)Z

    .line 130
    .line 131
    .line 132
    move-result p1

    .line 133
    if-eqz p1, :cond_6

    .line 134
    .line 135
    :goto_4
    iget-object p1, p0, Luo0/q;->k:Lro0/f;

    .line 136
    .line 137
    invoke-static {p1}, Lly0/q;->b(Ltr0/d;)Ljava/lang/Object;

    .line 138
    .line 139
    .line 140
    move-result-object p1

    .line 141
    check-cast p1, Lto0/h;

    .line 142
    .line 143
    if-eqz p1, :cond_8

    .line 144
    .line 145
    iget-object p1, p1, Lto0/h;->a:Ljava/lang/String;

    .line 146
    .line 147
    goto :goto_5

    .line 148
    :cond_8
    move-object p1, v3

    .line 149
    :goto_5
    :try_start_0
    invoke-static {v0, p2, p1}, Llp/v9;->b(Lto0/l;Ljava/lang/String;Ljava/lang/String;)Llp/v1;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 154
    .line 155
    .line 156
    move-result-object p2

    .line 157
    check-cast p2, Luo0/o;

    .line 158
    .line 159
    invoke-virtual {p2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 160
    .line 161
    .line 162
    new-instance p2, Luo0/o;

    .line 163
    .line 164
    invoke-direct {p2, v3, p1}, Luo0/o;-><init>(Lql0/g;Llp/v1;)V

    .line 165
    .line 166
    .line 167
    invoke-virtual {p0, p2}, Lql0/j;->g(Lql0/h;)V
    :try_end_0
    .catch Ljava/lang/IllegalArgumentException; {:try_start_0 .. :try_end_0} :catch_0

    .line 168
    .line 169
    .line 170
    return-object v1

    .line 171
    :catch_0
    move-exception v0

    .line 172
    move-object p1, v0

    .line 173
    move-object v5, p1

    .line 174
    invoke-virtual {p0}, Lql0/j;->a()Lql0/h;

    .line 175
    .line 176
    .line 177
    move-result-object p1

    .line 178
    check-cast p1, Luo0/o;

    .line 179
    .line 180
    new-instance v4, Lne0/c;

    .line 181
    .line 182
    const/4 v8, 0x0

    .line 183
    const/16 v9, 0x1e

    .line 184
    .line 185
    const/4 v6, 0x0

    .line 186
    const/4 v7, 0x0

    .line 187
    invoke-direct/range {v4 .. v9}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 188
    .line 189
    .line 190
    iget-object p2, p0, Luo0/q;->m:Lij0/a;

    .line 191
    .line 192
    invoke-static {v4, p2}, Ljp/rf;->e(Lne0/c;Lij0/a;)Lql0/g;

    .line 193
    .line 194
    .line 195
    move-result-object p2

    .line 196
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 197
    .line 198
    .line 199
    new-instance p1, Luo0/o;

    .line 200
    .line 201
    invoke-direct {p1, p2, v3}, Luo0/o;-><init>(Lql0/g;Llp/v1;)V

    .line 202
    .line 203
    .line 204
    invoke-virtual {p0, p1}, Lql0/j;->g(Lql0/h;)V

    .line 205
    .line 206
    .line 207
    return-object v1

    .line 208
    :cond_9
    new-instance p0, La8/r0;

    .line 209
    .line 210
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 211
    .line 212
    .line 213
    throw p0
.end method
