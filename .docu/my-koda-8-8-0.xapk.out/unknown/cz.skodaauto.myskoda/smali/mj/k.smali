.class public final Lmj/k;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llj/f;
.implements Lyi/a;
.implements Lmj/d;


# instance fields
.field public final a:Lvy0/b0;

.field public final b:Ll20/g;

.field public final c:Ll31/b;

.field public final d:Ll20/c;

.field public final e:Ljd/b;

.field public final f:Ll20/g;

.field public final g:Lmj/f;

.field public final h:Lyy0/c2;

.field public final i:Lez0/c;

.field public final j:Lyy0/c2;


# direct methods
.method public constructor <init>(Lvy0/b0;Ll20/g;Laj/a;Ljd/b;Ll31/b;Ll20/c;Ljd/b;Ll20/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lmj/k;->a:Lvy0/b0;

    .line 5
    .line 6
    iput-object p2, p0, Lmj/k;->b:Ll20/g;

    .line 7
    .line 8
    iput-object p5, p0, Lmj/k;->c:Ll31/b;

    .line 9
    .line 10
    iput-object p6, p0, Lmj/k;->d:Ll20/c;

    .line 11
    .line 12
    iput-object p7, p0, Lmj/k;->e:Ljd/b;

    .line 13
    .line 14
    iput-object p8, p0, Lmj/k;->f:Ll20/g;

    .line 15
    .line 16
    sget-object p2, Lgi/b;->f:Lgi/b;

    .line 17
    .line 18
    new-instance p3, Lmg/i;

    .line 19
    .line 20
    const/16 p4, 0x1b

    .line 21
    .line 22
    invoke-direct {p3, p4}, Lmg/i;-><init>(I)V

    .line 23
    .line 24
    .line 25
    sget-object p4, Lgi/a;->e:Lgi/a;

    .line 26
    .line 27
    const-class p5, Lmj/k;

    .line 28
    .line 29
    invoke-virtual {p5}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p5

    .line 33
    const/16 p7, 0x24

    .line 34
    .line 35
    invoke-static {p5, p7}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 36
    .line 37
    .line 38
    move-result-object p7

    .line 39
    const/16 p8, 0x2e

    .line 40
    .line 41
    invoke-static {p8, p7, p7}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 42
    .line 43
    .line 44
    move-result-object p7

    .line 45
    invoke-virtual {p7}, Ljava/lang/String;->length()I

    .line 46
    .line 47
    .line 48
    move-result p8

    .line 49
    if-nez p8, :cond_0

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_0
    const-string p5, "Kt"

    .line 53
    .line 54
    invoke-static {p7, p5}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 55
    .line 56
    .line 57
    move-result-object p5

    .line 58
    :goto_0
    const/4 p7, 0x0

    .line 59
    invoke-static {p5, p4, p2, p7, p3}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 60
    .line 61
    .line 62
    sget-object p2, Lmj/f;->a:Lmj/f;

    .line 63
    .line 64
    iput-object p2, p0, Lmj/k;->g:Lmj/f;

    .line 65
    .line 66
    invoke-virtual {p6}, Ll20/c;->invoke()Ljava/lang/Object;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    check-cast p2, Lnj/h;

    .line 71
    .line 72
    if-eqz p2, :cond_1

    .line 73
    .line 74
    invoke-virtual {p0, p2}, Lmj/k;->c(Lnj/h;)Lnj/h;

    .line 75
    .line 76
    .line 77
    move-result-object p2

    .line 78
    if-eqz p2, :cond_1

    .line 79
    .line 80
    new-instance p3, Lri/a;

    .line 81
    .line 82
    invoke-static {p2}, Lmj/f;->a(Lnj/h;)Llj/j;

    .line 83
    .line 84
    .line 85
    move-result-object p2

    .line 86
    invoke-direct {p3, p2}, Lri/a;-><init>(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    goto :goto_1

    .line 90
    :cond_1
    sget-object p3, Lri/b;->a:Lri/b;

    .line 91
    .line 92
    :goto_1
    invoke-static {p3}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 93
    .line 94
    .line 95
    move-result-object p2

    .line 96
    iput-object p2, p0, Lmj/k;->h:Lyy0/c2;

    .line 97
    .line 98
    invoke-static {}, Lez0/d;->a()Lez0/c;

    .line 99
    .line 100
    .line 101
    move-result-object p3

    .line 102
    iput-object p3, p0, Lmj/k;->i:Lez0/c;

    .line 103
    .line 104
    new-instance p3, Lm70/i0;

    .line 105
    .line 106
    const/16 p4, 0xa

    .line 107
    .line 108
    invoke-direct {p3, p0, p7, p4}, Lm70/i0;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 109
    .line 110
    .line 111
    const/4 p4, 0x3

    .line 112
    invoke-static {p1, p7, p7, p3, p4}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 113
    .line 114
    .line 115
    iput-object p2, p0, Lmj/k;->j:Lyy0/c2;

    .line 116
    .line 117
    return-void
.end method

.method public static final a(Lmj/k;Lrx0/c;)Ljava/lang/Object;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    instance-of v2, v1, Lmj/i;

    .line 6
    .line 7
    if-eqz v2, :cond_0

    .line 8
    .line 9
    move-object v2, v1

    .line 10
    check-cast v2, Lmj/i;

    .line 11
    .line 12
    iget v3, v2, Lmj/i;->h:I

    .line 13
    .line 14
    const/high16 v4, -0x80000000

    .line 15
    .line 16
    and-int v5, v3, v4

    .line 17
    .line 18
    if-eqz v5, :cond_0

    .line 19
    .line 20
    sub-int/2addr v3, v4

    .line 21
    iput v3, v2, Lmj/i;->h:I

    .line 22
    .line 23
    goto :goto_0

    .line 24
    :cond_0
    new-instance v2, Lmj/i;

    .line 25
    .line 26
    invoke-direct {v2, v0, v1}, Lmj/i;-><init>(Lmj/k;Lrx0/c;)V

    .line 27
    .line 28
    .line 29
    :goto_0
    iget-object v1, v2, Lmj/i;->f:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v3, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v4, v2, Lmj/i;->h:I

    .line 34
    .line 35
    const-string v5, "Kt"

    .line 36
    .line 37
    const/16 v6, 0x2e

    .line 38
    .line 39
    const/16 v7, 0x24

    .line 40
    .line 41
    const-class v8, Lmj/k;

    .line 42
    .line 43
    const/4 v9, 0x3

    .line 44
    const/4 v10, 0x1

    .line 45
    const/4 v11, 0x2

    .line 46
    const/4 v12, 0x0

    .line 47
    if-eqz v4, :cond_4

    .line 48
    .line 49
    if-eq v4, v10, :cond_3

    .line 50
    .line 51
    if-eq v4, v11, :cond_2

    .line 52
    .line 53
    if-ne v4, v9, :cond_1

    .line 54
    .line 55
    iget-object v2, v2, Lmj/i;->d:Lez0/a;

    .line 56
    .line 57
    :try_start_0
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 58
    .line 59
    .line 60
    goto/16 :goto_6

    .line 61
    .line 62
    :catchall_0
    move-exception v0

    .line 63
    goto/16 :goto_7

    .line 64
    .line 65
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 66
    .line 67
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 68
    .line 69
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw v0

    .line 73
    :cond_2
    iget v4, v2, Lmj/i;->e:I

    .line 74
    .line 75
    iget-object v10, v2, Lmj/i;->d:Lez0/a;

    .line 76
    .line 77
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 78
    .line 79
    .line 80
    move-object v1, v10

    .line 81
    goto :goto_3

    .line 82
    :cond_3
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 83
    .line 84
    .line 85
    goto :goto_1

    .line 86
    :cond_4
    invoke-static {v1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 87
    .line 88
    .line 89
    iget-object v1, v0, Lmj/k;->f:Ll20/g;

    .line 90
    .line 91
    iput v10, v2, Lmj/i;->h:I

    .line 92
    .line 93
    invoke-virtual {v1, v2}, Ll20/g;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    if-ne v1, v3, :cond_5

    .line 98
    .line 99
    goto/16 :goto_5

    .line 100
    .line 101
    :cond_5
    :goto_1
    sget-object v1, Lgi/b;->f:Lgi/b;

    .line 102
    .line 103
    new-instance v4, Lmg/i;

    .line 104
    .line 105
    const/16 v10, 0x1d

    .line 106
    .line 107
    invoke-direct {v4, v10}, Lmg/i;-><init>(I)V

    .line 108
    .line 109
    .line 110
    sget-object v10, Lgi/a;->e:Lgi/a;

    .line 111
    .line 112
    invoke-virtual {v8}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 113
    .line 114
    .line 115
    move-result-object v13

    .line 116
    invoke-static {v13, v7}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object v14

    .line 120
    invoke-static {v6, v14, v14}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 121
    .line 122
    .line 123
    move-result-object v14

    .line 124
    invoke-virtual {v14}, Ljava/lang/String;->length()I

    .line 125
    .line 126
    .line 127
    move-result v15

    .line 128
    if-nez v15, :cond_6

    .line 129
    .line 130
    goto :goto_2

    .line 131
    :cond_6
    invoke-static {v14, v5}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object v13

    .line 135
    :goto_2
    invoke-static {v13, v10, v1, v12, v4}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 136
    .line 137
    .line 138
    iget-object v1, v0, Lmj/k;->i:Lez0/c;

    .line 139
    .line 140
    iput-object v1, v2, Lmj/i;->d:Lez0/a;

    .line 141
    .line 142
    const/4 v4, 0x0

    .line 143
    iput v4, v2, Lmj/i;->e:I

    .line 144
    .line 145
    iput v11, v2, Lmj/i;->h:I

    .line 146
    .line 147
    invoke-virtual {v1, v2}, Lez0/c;->a(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object v10

    .line 151
    if-ne v10, v3, :cond_7

    .line 152
    .line 153
    goto :goto_5

    .line 154
    :cond_7
    :goto_3
    :try_start_1
    new-instance v10, Lmj/g;

    .line 155
    .line 156
    const/4 v11, 0x0

    .line 157
    invoke-direct {v10, v11}, Lmj/g;-><init>(I)V

    .line 158
    .line 159
    .line 160
    sget-object v11, Lgi/b;->e:Lgi/b;

    .line 161
    .line 162
    sget-object v13, Lgi/a;->e:Lgi/a;

    .line 163
    .line 164
    invoke-virtual {v8}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v8

    .line 168
    invoke-static {v8, v7}, Lly0/p;->f0(Ljava/lang/String;C)Ljava/lang/String;

    .line 169
    .line 170
    .line 171
    move-result-object v7

    .line 172
    invoke-static {v6, v7, v7}, Lly0/p;->e0(CLjava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 173
    .line 174
    .line 175
    move-result-object v6

    .line 176
    invoke-virtual {v6}, Ljava/lang/String;->length()I

    .line 177
    .line 178
    .line 179
    move-result v7

    .line 180
    if-nez v7, :cond_8

    .line 181
    .line 182
    goto :goto_4

    .line 183
    :cond_8
    invoke-static {v6, v5}, Lly0/p;->T(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 184
    .line 185
    .line 186
    move-result-object v8

    .line 187
    :goto_4
    invoke-static {v8, v13, v11, v12, v10}, Lkp/y8;->a(Ljava/lang/String;Lgi/a;Lgi/b;Ljava/lang/Throwable;Lay0/k;)V

    .line 188
    .line 189
    .line 190
    new-instance v5, Lmj/j;

    .line 191
    .line 192
    invoke-direct {v5, v0, v12}, Lmj/j;-><init>(Lmj/k;Lkotlin/coroutines/Continuation;)V

    .line 193
    .line 194
    .line 195
    new-instance v6, Lyy0/m1;

    .line 196
    .line 197
    invoke-direct {v6, v5}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 198
    .line 199
    .line 200
    new-instance v5, Lma0/c;

    .line 201
    .line 202
    const/4 v7, 0x2

    .line 203
    invoke-direct {v5, v0, v7}, Lma0/c;-><init>(Ljava/lang/Object;I)V

    .line 204
    .line 205
    .line 206
    iput-object v1, v2, Lmj/i;->d:Lez0/a;

    .line 207
    .line 208
    iput v4, v2, Lmj/i;->e:I

    .line 209
    .line 210
    iput v9, v2, Lmj/i;->h:I

    .line 211
    .line 212
    invoke-virtual {v6, v5, v2}, Lyy0/m1;->collect(Lyy0/j;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 213
    .line 214
    .line 215
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 216
    if-ne v0, v3, :cond_9

    .line 217
    .line 218
    :goto_5
    return-object v3

    .line 219
    :cond_9
    move-object v2, v1

    .line 220
    :goto_6
    invoke-interface {v2, v12}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 221
    .line 222
    .line 223
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 224
    .line 225
    return-object v0

    .line 226
    :catchall_1
    move-exception v0

    .line 227
    move-object v2, v1

    .line 228
    :goto_7
    invoke-interface {v2, v12}, Lez0/a;->d(Ljava/lang/Object;)V

    .line 229
    .line 230
    .line 231
    throw v0
.end method


# virtual methods
.method public final b()V
    .locals 3

    .line 1
    new-instance v0, Lk20/a;

    .line 2
    .line 3
    const/16 v1, 0x1b

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, p0, v2, v1}, Lk20/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 7
    .line 8
    .line 9
    const/4 v1, 0x3

    .line 10
    iget-object p0, p0, Lmj/k;->a:Lvy0/b0;

    .line 11
    .line 12
    invoke-static {p0, v2, v2, v0, v1}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public final c(Lnj/h;)Lnj/h;
    .locals 4

    .line 1
    iget-object v0, p1, Lnj/h;->b:Lnj/k;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object v0, v0, Lnj/k;->a:Lgz0/p;

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    invoke-virtual {v0}, Lgz0/p;->a()J

    .line 10
    .line 11
    .line 12
    move-result-wide v0

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const-wide/16 v0, 0x0

    .line 15
    .line 16
    :goto_0
    iget-object p0, p0, Lmj/k;->c:Ll31/b;

    .line 17
    .line 18
    invoke-virtual {p0}, Ll31/b;->invoke()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object p0

    .line 22
    check-cast p0, Ljava/lang/Number;

    .line 23
    .line 24
    invoke-virtual {p0}, Ljava/lang/Number;->longValue()J

    .line 25
    .line 26
    .line 27
    move-result-wide v2

    .line 28
    cmp-long p0, v0, v2

    .line 29
    .line 30
    if-lez p0, :cond_1

    .line 31
    .line 32
    return-object p1

    .line 33
    :cond_1
    const/4 p0, 0x0

    .line 34
    return-object p0
.end method
