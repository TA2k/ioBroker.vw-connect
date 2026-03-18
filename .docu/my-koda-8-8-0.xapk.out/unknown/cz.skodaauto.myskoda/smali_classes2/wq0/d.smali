.class public final Lwq0/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lwq0/r;

.field public final b:Lzd0/c;

.field public final c:Lwq0/g;

.field public final d:Lwq0/l0;


# direct methods
.method public constructor <init>(Lwq0/r;Lzd0/c;Lwq0/g;Lwq0/l0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwq0/d;->a:Lwq0/r;

    .line 5
    .line 6
    iput-object p2, p0, Lwq0/d;->b:Lzd0/c;

    .line 7
    .line 8
    iput-object p3, p0, Lwq0/d;->c:Lwq0/g;

    .line 9
    .line 10
    iput-object p4, p0, Lwq0/d;->d:Lwq0/l0;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lwq0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p1, Lwq0/b;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lwq0/b;

    .line 7
    .line 8
    iget v1, v0, Lwq0/b;->h:I

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
    iput v1, v0, Lwq0/b;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwq0/b;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lwq0/b;-><init>(Lwq0/d;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lwq0/b;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwq0/b;->h:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x1

    .line 33
    iget-object v5, p0, Lwq0/d;->a:Lwq0/r;

    .line 34
    .line 35
    const/4 v6, 0x0

    .line 36
    if-eqz v2, :cond_3

    .line 37
    .line 38
    if-eq v2, v4, :cond_2

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    iget-object p0, v0, Lwq0/b;->d:Lez0/a;

    .line 43
    .line 44
    :try_start_0
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    .line 46
    .line 47
    goto :goto_3

    .line 48
    :catchall_0
    move-exception p1

    .line 49
    goto :goto_4

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
    iget v2, v0, Lwq0/b;->e:I

    .line 59
    .line 60
    iget-object v4, v0, Lwq0/b;->d:Lez0/a;

    .line 61
    .line 62
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 63
    .line 64
    .line 65
    move-object p1, v4

    .line 66
    goto :goto_1

    .line 67
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    move-object p1, v5

    .line 71
    check-cast p1, Ltq0/a;

    .line 72
    .line 73
    iget-object p1, p1, Ltq0/a;->a:Lez0/c;

    .line 74
    .line 75
    iput-object p1, v0, Lwq0/b;->d:Lez0/a;

    .line 76
    .line 77
    const/4 v2, 0x0

    .line 78
    iput v2, v0, Lwq0/b;->e:I

    .line 79
    .line 80
    iput v4, v0, Lwq0/b;->h:I

    .line 81
    .line 82
    invoke-virtual {p1, v0}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v4

    .line 86
    if-ne v4, v1, :cond_4

    .line 87
    .line 88
    goto :goto_2

    .line 89
    :cond_4
    :goto_1
    :try_start_1
    sget-object v4, Lyq0/n;->e:Lyq0/n;

    .line 90
    .line 91
    move-object v7, v5

    .line 92
    check-cast v7, Ltq0/a;

    .line 93
    .line 94
    iput-object v4, v7, Ltq0/a;->d:Lyq0/n;

    .line 95
    .line 96
    iput-object p1, v0, Lwq0/b;->d:Lez0/a;

    .line 97
    .line 98
    iput v2, v0, Lwq0/b;->e:I

    .line 99
    .line 100
    iput v3, v0, Lwq0/b;->h:I

    .line 101
    .line 102
    invoke-virtual {p0, v0}, Lwq0/d;->c(Lrx0/c;)Ljava/lang/Object;

    .line 103
    .line 104
    .line 105
    move-result-object p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 106
    if-ne p0, v1, :cond_5

    .line 107
    .line 108
    :goto_2
    return-object v1

    .line 109
    :cond_5
    move-object p0, p1

    .line 110
    :goto_3
    :try_start_2
    move-object p1, v5

    .line 111
    check-cast p1, Ltq0/a;

    .line 112
    .line 113
    iput-object v6, p1, Ltq0/a;->d:Lyq0/n;

    .line 114
    .line 115
    check-cast v5, Ltq0/a;

    .line 116
    .line 117
    iput-object v6, v5, Ltq0/a;->b:Ljava/lang/String;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 118
    .line 119
    invoke-interface {p0, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 120
    .line 121
    .line 122
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 123
    .line 124
    return-object p0

    .line 125
    :catchall_1
    move-exception p0

    .line 126
    move-object v8, p1

    .line 127
    move-object p1, p0

    .line 128
    move-object p0, v8

    .line 129
    :goto_4
    invoke-interface {p0, v6}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 130
    .line 131
    .line 132
    throw p1
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 12

    .line 1
    iget-object v0, p0, Lwq0/d;->b:Lzd0/c;

    .line 2
    .line 3
    iget-object v0, v0, Lzd0/c;->a:Lxd0/b;

    .line 4
    .line 5
    instance-of v1, p1, Lwq0/c;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    move-object v1, p1

    .line 10
    check-cast v1, Lwq0/c;

    .line 11
    .line 12
    iget v2, v1, Lwq0/c;->g:I

    .line 13
    .line 14
    const/high16 v3, -0x80000000

    .line 15
    .line 16
    and-int v4, v2, v3

    .line 17
    .line 18
    if-eqz v4, :cond_0

    .line 19
    .line 20
    sub-int/2addr v2, v3

    .line 21
    iput v2, v1, Lwq0/c;->g:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v1, Lwq0/c;

    .line 25
    .line 26
    invoke-direct {v1, p0, p1}, Lwq0/c;-><init>(Lwq0/d;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object p1, v1, Lwq0/c;->e:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v3, v1, Lwq0/c;->g:I

    .line 34
    .line 35
    const/4 v4, 0x0

    .line 36
    const/4 v5, 0x5

    .line 37
    const/4 v6, 0x4

    .line 38
    const/4 v7, 0x3

    .line 39
    const/4 v8, 0x2

    .line 40
    const/4 v9, 0x1

    .line 41
    sget-object v10, Llx0/b0;->a:Llx0/b0;

    .line 42
    .line 43
    if-eqz v3, :cond_6

    .line 44
    .line 45
    if-eq v3, v9, :cond_5

    .line 46
    .line 47
    if-eq v3, v8, :cond_4

    .line 48
    .line 49
    if-eq v3, v7, :cond_3

    .line 50
    .line 51
    if-eq v3, v6, :cond_2

    .line 52
    .line 53
    if-ne v3, v5, :cond_1

    .line 54
    .line 55
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    return-object v10

    .line 59
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 62
    .line 63
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw p0

    .line 67
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    goto/16 :goto_8

    .line 71
    .line 72
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    goto/16 :goto_7

    .line 76
    .line 77
    :cond_4
    iget-object v3, v1, Lwq0/c;->d:Lne0/t;

    .line 78
    .line 79
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 80
    .line 81
    .line 82
    goto :goto_4

    .line 83
    :cond_5
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 84
    .line 85
    .line 86
    goto :goto_1

    .line 87
    :cond_6
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 88
    .line 89
    .line 90
    :cond_7
    iput-object v4, v1, Lwq0/c;->d:Lne0/t;

    .line 91
    .line 92
    iput v9, v1, Lwq0/c;->g:I

    .line 93
    .line 94
    sget-object p1, Lyq0/o;->a:Lyq0/o;

    .line 95
    .line 96
    invoke-virtual {v0, p1, v1}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object p1

    .line 100
    if-ne p1, v2, :cond_8

    .line 101
    .line 102
    goto/16 :goto_9

    .line 103
    .line 104
    :cond_8
    :goto_1
    move-object v3, p1

    .line 105
    check-cast v3, Lne0/t;

    .line 106
    .line 107
    instance-of p1, v3, Lne0/c;

    .line 108
    .line 109
    if-eqz p1, :cond_9

    .line 110
    .line 111
    move-object v11, v3

    .line 112
    check-cast v11, Lne0/c;

    .line 113
    .line 114
    goto :goto_2

    .line 115
    :cond_9
    move-object v11, v4

    .line 116
    :goto_2
    if-eqz v11, :cond_a

    .line 117
    .line 118
    iget-object v11, v11, Lne0/c;->a:Ljava/lang/Throwable;

    .line 119
    .line 120
    goto :goto_3

    .line 121
    :cond_a
    move-object v11, v4

    .line 122
    :goto_3
    instance-of v11, v11, Lyq0/j;

    .line 123
    .line 124
    if-eqz v11, :cond_c

    .line 125
    .line 126
    iput-object v3, v1, Lwq0/c;->d:Lne0/t;

    .line 127
    .line 128
    iput v8, v1, Lwq0/c;->g:I

    .line 129
    .line 130
    iget-object p1, p0, Lwq0/d;->d:Lwq0/l0;

    .line 131
    .line 132
    invoke-virtual {p1, v1}, Lwq0/l0;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p1

    .line 136
    if-ne p1, v2, :cond_b

    .line 137
    .line 138
    goto :goto_9

    .line 139
    :cond_b
    :goto_4
    instance-of p1, p1, Lne0/e;

    .line 140
    .line 141
    if-eqz p1, :cond_d

    .line 142
    .line 143
    goto :goto_a

    .line 144
    :cond_c
    if-eqz p1, :cond_d

    .line 145
    .line 146
    goto :goto_a

    .line 147
    :cond_d
    instance-of p1, v3, Lne0/c;

    .line 148
    .line 149
    if-eqz p1, :cond_e

    .line 150
    .line 151
    check-cast v3, Lne0/c;

    .line 152
    .line 153
    goto :goto_5

    .line 154
    :cond_e
    move-object v3, v4

    .line 155
    :goto_5
    if-eqz v3, :cond_f

    .line 156
    .line 157
    iget-object p1, v3, Lne0/c;->a:Ljava/lang/Throwable;

    .line 158
    .line 159
    goto :goto_6

    .line 160
    :cond_f
    move-object p1, v4

    .line 161
    :goto_6
    instance-of p1, p1, Lyq0/j;

    .line 162
    .line 163
    if-nez p1, :cond_7

    .line 164
    .line 165
    iput-object v4, v1, Lwq0/c;->d:Lne0/t;

    .line 166
    .line 167
    iput v7, v1, Lwq0/c;->g:I

    .line 168
    .line 169
    sget-object p1, Lyq0/h;->a:Lyq0/h;

    .line 170
    .line 171
    invoke-virtual {v0, p1, v1}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object p1

    .line 175
    if-ne p1, v2, :cond_10

    .line 176
    .line 177
    goto :goto_9

    .line 178
    :cond_10
    :goto_7
    check-cast p1, Lne0/t;

    .line 179
    .line 180
    instance-of p1, p1, Lne0/c;

    .line 181
    .line 182
    if-eqz p1, :cond_11

    .line 183
    .line 184
    goto :goto_a

    .line 185
    :cond_11
    iput v6, v1, Lwq0/c;->g:I

    .line 186
    .line 187
    iget-object p0, p0, Lwq0/d;->c:Lwq0/g;

    .line 188
    .line 189
    invoke-virtual {p0, v10, v1}, Lwq0/g;->a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 190
    .line 191
    .line 192
    move-result-object p1

    .line 193
    if-ne p1, v2, :cond_12

    .line 194
    .line 195
    goto :goto_9

    .line 196
    :cond_12
    :goto_8
    sget-object p0, Lyq0/a;->a:Lyq0/a;

    .line 197
    .line 198
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 199
    .line 200
    .line 201
    move-result p0

    .line 202
    if-eqz p0, :cond_13

    .line 203
    .line 204
    iput v5, v1, Lwq0/c;->g:I

    .line 205
    .line 206
    sget-object p0, Lyq0/f;->a:Lyq0/f;

    .line 207
    .line 208
    invoke-virtual {v0, p0, v1}, Lxd0/b;->a(Lae0/a;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 209
    .line 210
    .line 211
    move-result-object p0

    .line 212
    if-ne p0, v2, :cond_13

    .line 213
    .line 214
    :goto_9
    return-object v2

    .line 215
    :cond_13
    :goto_a
    return-object v10
.end method
