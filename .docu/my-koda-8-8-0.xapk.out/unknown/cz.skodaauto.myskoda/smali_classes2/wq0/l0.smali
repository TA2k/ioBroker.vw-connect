.class public final Lwq0/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lzd0/c;

.field public final b:Lwq0/w;

.field public final c:Lwq0/r;

.field public final d:Lwq0/p0;

.field public final e:Lgb0/m;


# direct methods
.method public constructor <init>(Lzd0/c;Lwq0/w;Lwq0/r;Lwq0/p0;Lgb0/m;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwq0/l0;->a:Lzd0/c;

    .line 5
    .line 6
    iput-object p2, p0, Lwq0/l0;->b:Lwq0/w;

    .line 7
    .line 8
    iput-object p3, p0, Lwq0/l0;->c:Lwq0/r;

    .line 9
    .line 10
    iput-object p4, p0, Lwq0/l0;->d:Lwq0/p0;

    .line 11
    .line 12
    iput-object p5, p0, Lwq0/l0;->e:Lgb0/m;

    .line 13
    .line 14
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lwq0/l0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p1, Lwq0/j0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lwq0/j0;

    .line 7
    .line 8
    iget v1, v0, Lwq0/j0;->g:I

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
    iput v1, v0, Lwq0/j0;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwq0/j0;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lwq0/j0;-><init>(Lwq0/l0;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lwq0/j0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwq0/j0;->g:I

    .line 30
    .line 31
    iget-object v3, p0, Lwq0/l0;->c:Lwq0/r;

    .line 32
    .line 33
    const/4 v4, 0x1

    .line 34
    if-eqz v2, :cond_2

    .line 35
    .line 36
    if-ne v2, v4, :cond_1

    .line 37
    .line 38
    iget-object p0, v0, Lwq0/j0;->d:Lyq0/n;

    .line 39
    .line 40
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 41
    .line 42
    .line 43
    goto :goto_1

    .line 44
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 45
    .line 46
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 47
    .line 48
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 49
    .line 50
    .line 51
    throw p0

    .line 52
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 53
    .line 54
    .line 55
    move-object p1, v3

    .line 56
    check-cast p1, Ltq0/a;

    .line 57
    .line 58
    iget-object v2, p1, Ltq0/a;->d:Lyq0/n;

    .line 59
    .line 60
    sget-object v5, Lyq0/n;->g:Lyq0/n;

    .line 61
    .line 62
    iput-object v5, p1, Ltq0/a;->d:Lyq0/n;

    .line 63
    .line 64
    iput-object v2, v0, Lwq0/j0;->d:Lyq0/n;

    .line 65
    .line 66
    iput v4, v0, Lwq0/j0;->g:I

    .line 67
    .line 68
    invoke-virtual {p0, v0}, Lwq0/l0;->c(Lrx0/c;)Ljava/lang/Object;

    .line 69
    .line 70
    .line 71
    move-result-object p1

    .line 72
    if-ne p1, v1, :cond_3

    .line 73
    .line 74
    return-object v1

    .line 75
    :cond_3
    move-object p0, v2

    .line 76
    :goto_1
    check-cast p1, Lne0/t;

    .line 77
    .line 78
    check-cast v3, Ltq0/a;

    .line 79
    .line 80
    iput-object p0, v3, Ltq0/a;->d:Lyq0/n;

    .line 81
    .line 82
    return-object p1
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    iget-object v0, p0, Lwq0/l0;->d:Lwq0/p0;

    .line 2
    .line 3
    iget-object v0, v0, Lwq0/p0;->a:Lwq0/r;

    .line 4
    .line 5
    iget-object v1, p0, Lwq0/l0;->a:Lzd0/c;

    .line 6
    .line 7
    iget-object v1, v1, Lzd0/c;->a:Lxd0/b;

    .line 8
    .line 9
    instance-of v2, p1, Lwq0/k0;

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    move-object v2, p1

    .line 14
    check-cast v2, Lwq0/k0;

    .line 15
    .line 16
    iget v3, v2, Lwq0/k0;->f:I

    .line 17
    .line 18
    const/high16 v4, -0x80000000

    .line 19
    .line 20
    and-int v5, v3, v4

    .line 21
    .line 22
    if-eqz v5, :cond_0

    .line 23
    .line 24
    sub-int/2addr v3, v4

    .line 25
    iput v3, v2, Lwq0/k0;->f:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v2, Lwq0/k0;

    .line 29
    .line 30
    invoke-direct {v2, p0, p1}, Lwq0/k0;-><init>(Lwq0/l0;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object p1, v2, Lwq0/k0;->d:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v4, v2, Lwq0/k0;->f:I

    .line 38
    .line 39
    const/4 v5, 0x5

    .line 40
    const/4 v6, 0x4

    .line 41
    const/4 v7, 0x3

    .line 42
    const/4 v8, 0x2

    .line 43
    const/4 v9, 0x1

    .line 44
    const/4 v10, 0x0

    .line 45
    if-eqz v4, :cond_6

    .line 46
    .line 47
    if-eq v4, v9, :cond_5

    .line 48
    .line 49
    if-eq v4, v8, :cond_4

    .line 50
    .line 51
    if-eq v4, v7, :cond_3

    .line 52
    .line 53
    if-eq v4, v6, :cond_2

    .line 54
    .line 55
    if-ne v4, v5, :cond_1

    .line 56
    .line 57
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto/16 :goto_6

    .line 61
    .line 62
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 63
    .line 64
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 65
    .line 66
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 67
    .line 68
    .line 69
    throw p0

    .line 70
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 71
    .line 72
    .line 73
    goto :goto_4

    .line 74
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 75
    .line 76
    .line 77
    goto :goto_3

    .line 78
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 79
    .line 80
    .line 81
    goto :goto_2

    .line 82
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    move-object p1, v0

    .line 90
    check-cast p1, Ltq0/a;

    .line 91
    .line 92
    iput-object v10, p1, Ltq0/a;->c:Ljava/lang/String;

    .line 93
    .line 94
    iput v9, v2, Lwq0/k0;->f:I

    .line 95
    .line 96
    sget-object p1, Lyq0/q;->a:Lyq0/q;

    .line 97
    .line 98
    invoke-virtual {v1, p1, v2}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    if-ne p1, v3, :cond_7

    .line 103
    .line 104
    goto :goto_5

    .line 105
    :cond_7
    :goto_1
    check-cast p1, Lne0/t;

    .line 106
    .line 107
    instance-of v4, p1, Lne0/c;

    .line 108
    .line 109
    if-eqz v4, :cond_8

    .line 110
    .line 111
    check-cast p1, Lne0/c;

    .line 112
    .line 113
    return-object p1

    .line 114
    :cond_8
    iput v8, v2, Lwq0/k0;->f:I

    .line 115
    .line 116
    sget-object p1, Lyq0/h;->a:Lyq0/h;

    .line 117
    .line 118
    invoke-virtual {v1, p1, v2}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 119
    .line 120
    .line 121
    move-result-object p1

    .line 122
    if-ne p1, v3, :cond_9

    .line 123
    .line 124
    goto :goto_5

    .line 125
    :cond_9
    :goto_2
    check-cast p1, Lne0/t;

    .line 126
    .line 127
    instance-of v4, p1, Lne0/c;

    .line 128
    .line 129
    if-eqz v4, :cond_a

    .line 130
    .line 131
    check-cast p1, Lne0/c;

    .line 132
    .line 133
    return-object p1

    .line 134
    :cond_a
    iput v7, v2, Lwq0/k0;->f:I

    .line 135
    .line 136
    sget-object p1, Lyq0/s;->a:Lyq0/s;

    .line 137
    .line 138
    invoke-virtual {v1, p1, v2}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    if-ne p1, v3, :cond_b

    .line 143
    .line 144
    goto :goto_5

    .line 145
    :cond_b
    :goto_3
    check-cast p1, Lne0/t;

    .line 146
    .line 147
    instance-of v4, p1, Lne0/c;

    .line 148
    .line 149
    if-eqz v4, :cond_c

    .line 150
    .line 151
    check-cast p1, Lne0/c;

    .line 152
    .line 153
    return-object p1

    .line 154
    :cond_c
    iput v6, v2, Lwq0/k0;->f:I

    .line 155
    .line 156
    sget-object p1, Lyq0/r;->a:Lyq0/r;

    .line 157
    .line 158
    invoke-virtual {v1, p1, v2}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 159
    .line 160
    .line 161
    move-result-object p1

    .line 162
    if-ne p1, v3, :cond_d

    .line 163
    .line 164
    goto :goto_5

    .line 165
    :cond_d
    :goto_4
    check-cast p1, Lne0/t;

    .line 166
    .line 167
    instance-of v4, p1, Lne0/c;

    .line 168
    .line 169
    if-eqz v4, :cond_e

    .line 170
    .line 171
    check-cast p1, Lne0/c;

    .line 172
    .line 173
    check-cast v0, Ltq0/a;

    .line 174
    .line 175
    iput-object v10, v0, Ltq0/a;->c:Ljava/lang/String;

    .line 176
    .line 177
    return-object p1

    .line 178
    :cond_e
    iput v5, v2, Lwq0/k0;->f:I

    .line 179
    .line 180
    sget-object p1, Lyq0/p;->a:Lyq0/p;

    .line 181
    .line 182
    invoke-virtual {v1, p1, v2}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object p1

    .line 186
    if-ne p1, v3, :cond_f

    .line 187
    .line 188
    :goto_5
    return-object v3

    .line 189
    :cond_f
    :goto_6
    check-cast p1, Lne0/t;

    .line 190
    .line 191
    instance-of p1, p1, Lne0/e;

    .line 192
    .line 193
    if-eqz p1, :cond_8

    .line 194
    .line 195
    iget-object p1, p0, Lwq0/l0;->e:Lgb0/m;

    .line 196
    .line 197
    invoke-virtual {p1}, Lgb0/m;->invoke()Ljava/lang/Object;

    .line 198
    .line 199
    .line 200
    iget-object p0, p0, Lwq0/l0;->b:Lwq0/w;

    .line 201
    .line 202
    invoke-virtual {p0}, Lwq0/w;->invoke()Ljava/lang/Object;

    .line 203
    .line 204
    .line 205
    new-instance p0, Lne0/e;

    .line 206
    .line 207
    sget-object p1, Llx0/b0;->a:Llx0/b0;

    .line 208
    .line 209
    invoke-direct {p0, p1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 210
    .line 211
    .line 212
    return-object p0
.end method
