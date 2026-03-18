.class public final Li2/p;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Lh2/n8;

.field public final b:Lay0/a;

.field public final c:Ld2/g;

.field public final d:Lay0/k;

.field public final e:Li2/o0;

.field public final f:Li2/o;

.field public final g:Ll2/j1;

.field public final h:Ll2/h0;

.field public final i:Ll2/h0;

.field public final j:Ll2/f1;

.field public final k:Ll2/f1;

.field public final l:Ll2/j1;

.field public final m:Ll2/j1;

.field public final n:Li2/n;


# direct methods
.method public constructor <init>(Lh2/s8;Lh2/n8;Lay0/a;Ld2/g;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Li2/p;->a:Lh2/n8;

    .line 5
    .line 6
    iput-object p3, p0, Li2/p;->b:Lay0/a;

    .line 7
    .line 8
    iput-object p4, p0, Li2/p;->c:Ld2/g;

    .line 9
    .line 10
    iput-object p5, p0, Li2/p;->d:Lay0/k;

    .line 11
    .line 12
    new-instance p2, Li2/o0;

    .line 13
    .line 14
    invoke-direct {p2}, Li2/o0;-><init>()V

    .line 15
    .line 16
    .line 17
    iput-object p2, p0, Li2/p;->e:Li2/o0;

    .line 18
    .line 19
    new-instance p2, Li2/o;

    .line 20
    .line 21
    invoke-direct {p2, p0}, Li2/o;-><init>(Li2/p;)V

    .line 22
    .line 23
    .line 24
    iput-object p2, p0, Li2/p;->f:Li2/o;

    .line 25
    .line 26
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 27
    .line 28
    .line 29
    move-result-object p1

    .line 30
    iput-object p1, p0, Li2/p;->g:Ll2/j1;

    .line 31
    .line 32
    new-instance p1, Li2/k;

    .line 33
    .line 34
    const/4 p2, 0x0

    .line 35
    invoke-direct {p1, p0, p2}, Li2/k;-><init>(Li2/p;I)V

    .line 36
    .line 37
    .line 38
    invoke-static {p1}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 39
    .line 40
    .line 41
    move-result-object p1

    .line 42
    iput-object p1, p0, Li2/p;->h:Ll2/h0;

    .line 43
    .line 44
    new-instance p1, Li2/k;

    .line 45
    .line 46
    const/4 p2, 0x1

    .line 47
    invoke-direct {p1, p0, p2}, Li2/k;-><init>(Li2/p;I)V

    .line 48
    .line 49
    .line 50
    invoke-static {p1}, Ll2/b;->h(Lay0/a;)Ll2/h0;

    .line 51
    .line 52
    .line 53
    move-result-object p1

    .line 54
    iput-object p1, p0, Li2/p;->i:Ll2/h0;

    .line 55
    .line 56
    new-instance p1, Ll2/f1;

    .line 57
    .line 58
    const/high16 p2, 0x7fc00000    # Float.NaN

    .line 59
    .line 60
    invoke-direct {p1, p2}, Ll2/f1;-><init>(F)V

    .line 61
    .line 62
    .line 63
    iput-object p1, p0, Li2/p;->j:Ll2/f1;

    .line 64
    .line 65
    sget-object p1, Ll2/x0;->i:Ll2/x0;

    .line 66
    .line 67
    new-instance p2, Li2/k;

    .line 68
    .line 69
    const/4 p3, 0x2

    .line 70
    invoke-direct {p2, p0, p3}, Li2/k;-><init>(Li2/p;I)V

    .line 71
    .line 72
    .line 73
    invoke-static {p2, p1}, Ll2/b;->i(Lay0/a;Ll2/n2;)Ll2/h0;

    .line 74
    .line 75
    .line 76
    new-instance p1, Ll2/f1;

    .line 77
    .line 78
    const/4 p2, 0x0

    .line 79
    invoke-direct {p1, p2}, Ll2/f1;-><init>(F)V

    .line 80
    .line 81
    .line 82
    iput-object p1, p0, Li2/p;->k:Ll2/f1;

    .line 83
    .line 84
    const/4 p1, 0x0

    .line 85
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 86
    .line 87
    .line 88
    move-result-object p1

    .line 89
    iput-object p1, p0, Li2/p;->l:Ll2/j1;

    .line 90
    .line 91
    new-instance p1, Li2/u0;

    .line 92
    .line 93
    sget-object p2, Lmx0/t;->d:Lmx0/t;

    .line 94
    .line 95
    invoke-direct {p1, p2}, Li2/u0;-><init>(Ljava/util/Map;)V

    .line 96
    .line 97
    .line 98
    invoke-static {p1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 99
    .line 100
    .line 101
    move-result-object p1

    .line 102
    iput-object p1, p0, Li2/p;->m:Ll2/j1;

    .line 103
    .line 104
    new-instance p1, Li2/n;

    .line 105
    .line 106
    invoke-direct {p1, p0}, Li2/n;-><init>(Li2/p;)V

    .line 107
    .line 108
    .line 109
    iput-object p1, p0, Li2/p;->n:Li2/n;

    .line 110
    .line 111
    return-void
.end method


# virtual methods
.method public final a(Le1/w0;La7/l0;Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p3, Li2/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Li2/l;

    .line 7
    .line 8
    iget v1, v0, Li2/l;->f:I

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
    iput v1, v0, Li2/l;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Li2/l;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Li2/l;-><init>(Li2/p;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Li2/l;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Li2/l;->f:I

    .line 30
    .line 31
    iget-object v3, p0, Li2/p;->j:Ll2/f1;

    .line 32
    .line 33
    iget-object v4, p0, Li2/p;->d:Lay0/k;

    .line 34
    .line 35
    const/high16 v5, 0x3f000000    # 0.5f

    .line 36
    .line 37
    const/4 v6, 0x1

    .line 38
    if-eqz v2, :cond_2

    .line 39
    .line 40
    if-ne v2, v6, :cond_1

    .line 41
    .line 42
    :try_start_0
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 43
    .line 44
    .line 45
    goto :goto_1

    .line 46
    :catchall_0
    move-exception p1

    .line 47
    goto :goto_2

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
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    :try_start_1
    iget-object p3, p0, Li2/p;->e:Li2/o0;

    .line 60
    .line 61
    new-instance v2, La2/c;

    .line 62
    .line 63
    const/16 v7, 0xf

    .line 64
    .line 65
    const/4 v8, 0x0

    .line 66
    invoke-direct {v2, v7, p0, p2, v8}, La2/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 67
    .line 68
    .line 69
    iput v6, v0, Li2/l;->f:I

    .line 70
    .line 71
    invoke-virtual {p3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    new-instance p2, Le1/z0;

    .line 75
    .line 76
    invoke-direct {p2, p1, p3, v2, v8}, Le1/z0;-><init>(Le1/w0;Li2/o0;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 77
    .line 78
    .line 79
    invoke-static {p2, v0}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object p1
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 83
    if-ne p1, v1, :cond_3

    .line 84
    .line 85
    return-object v1

    .line 86
    :cond_3
    :goto_1
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 87
    .line 88
    .line 89
    move-result-object p1

    .line 90
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 91
    .line 92
    .line 93
    move-result p2

    .line 94
    invoke-virtual {p1, p2}, Li2/u0;->a(F)Ljava/lang/Object;

    .line 95
    .line 96
    .line 97
    move-result-object p1

    .line 98
    if-eqz p1, :cond_4

    .line 99
    .line 100
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 101
    .line 102
    .line 103
    move-result p2

    .line 104
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 105
    .line 106
    .line 107
    move-result-object p3

    .line 108
    invoke-virtual {p3, p1}, Li2/u0;->d(Ljava/lang/Object;)F

    .line 109
    .line 110
    .line 111
    move-result p3

    .line 112
    sub-float/2addr p2, p3

    .line 113
    invoke-static {p2}, Ljava/lang/Math;->abs(F)F

    .line 114
    .line 115
    .line 116
    move-result p2

    .line 117
    cmpg-float p2, p2, v5

    .line 118
    .line 119
    if-gtz p2, :cond_4

    .line 120
    .line 121
    invoke-interface {v4, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object p2

    .line 125
    check-cast p2, Ljava/lang/Boolean;

    .line 126
    .line 127
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 128
    .line 129
    .line 130
    move-result p2

    .line 131
    if-eqz p2, :cond_4

    .line 132
    .line 133
    invoke-virtual {p0, p1}, Li2/p;->g(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    :cond_4
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 137
    .line 138
    return-object p0

    .line 139
    :goto_2
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 140
    .line 141
    .line 142
    move-result-object p2

    .line 143
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 144
    .line 145
    .line 146
    move-result p3

    .line 147
    invoke-virtual {p2, p3}, Li2/u0;->a(F)Ljava/lang/Object;

    .line 148
    .line 149
    .line 150
    move-result-object p2

    .line 151
    if-eqz p2, :cond_5

    .line 152
    .line 153
    invoke-virtual {v3}, Ll2/f1;->o()F

    .line 154
    .line 155
    .line 156
    move-result p3

    .line 157
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 158
    .line 159
    .line 160
    move-result-object v0

    .line 161
    invoke-virtual {v0, p2}, Li2/u0;->d(Ljava/lang/Object;)F

    .line 162
    .line 163
    .line 164
    move-result v0

    .line 165
    sub-float/2addr p3, v0

    .line 166
    invoke-static {p3}, Ljava/lang/Math;->abs(F)F

    .line 167
    .line 168
    .line 169
    move-result p3

    .line 170
    cmpg-float p3, p3, v5

    .line 171
    .line 172
    if-gtz p3, :cond_5

    .line 173
    .line 174
    invoke-interface {v4, p2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object p3

    .line 178
    check-cast p3, Ljava/lang/Boolean;

    .line 179
    .line 180
    invoke-virtual {p3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 181
    .line 182
    .line 183
    move-result p3

    .line 184
    if-eqz p3, :cond_5

    .line 185
    .line 186
    invoke-virtual {p0, p2}, Li2/p;->g(Ljava/lang/Object;)V

    .line 187
    .line 188
    .line 189
    :cond_5
    throw p1
.end method

.method public final b(Ljava/lang/Object;Le1/w0;Lay0/p;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 13

    .line 1
    move-object/from16 v0, p4

    .line 2
    .line 3
    instance-of v1, v0, Li2/m;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, v0

    .line 8
    check-cast v1, Li2/m;

    .line 9
    .line 10
    iget v3, v1, Li2/m;->f:I

    .line 11
    .line 12
    const/high16 v4, -0x80000000

    .line 13
    .line 14
    and-int v5, v3, v4

    .line 15
    .line 16
    if-eqz v5, :cond_0

    .line 17
    .line 18
    sub-int/2addr v3, v4

    .line 19
    iput v3, v1, Li2/m;->f:I

    .line 20
    .line 21
    :goto_0
    move-object v6, v1

    .line 22
    goto :goto_1

    .line 23
    :cond_0
    new-instance v1, Li2/m;

    .line 24
    .line 25
    invoke-direct {v1, p0, v0}, Li2/m;-><init>(Li2/p;Lkotlin/coroutines/Continuation;)V

    .line 26
    .line 27
    .line 28
    goto :goto_0

    .line 29
    :goto_1
    iget-object v0, v6, Li2/m;->d:Ljava/lang/Object;

    .line 30
    .line 31
    sget-object v7, Lqx0/a;->d:Lqx0/a;

    .line 32
    .line 33
    iget v1, v6, Li2/m;->f:I

    .line 34
    .line 35
    iget-object v8, p0, Li2/p;->j:Ll2/f1;

    .line 36
    .line 37
    iget-object v9, p0, Li2/p;->d:Lay0/k;

    .line 38
    .line 39
    const/high16 v10, 0x3f000000    # 0.5f

    .line 40
    .line 41
    const/4 v11, 0x1

    .line 42
    const/4 v5, 0x0

    .line 43
    if-eqz v1, :cond_2

    .line 44
    .line 45
    if-ne v1, v11, :cond_1

    .line 46
    .line 47
    :try_start_0
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 48
    .line 49
    .line 50
    goto :goto_2

    .line 51
    :catchall_0
    move-exception v0

    .line 52
    goto :goto_3

    .line 53
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 54
    .line 55
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 56
    .line 57
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 58
    .line 59
    .line 60
    throw v0

    .line 61
    :cond_2
    invoke-static {v0}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 65
    .line 66
    .line 67
    move-result-object v0

    .line 68
    iget-object v0, v0, Li2/u0;->a:Ljava/util/Map;

    .line 69
    .line 70
    invoke-interface {v0, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 71
    .line 72
    .line 73
    move-result v0

    .line 74
    if-eqz v0, :cond_5

    .line 75
    .line 76
    :try_start_1
    iget-object v12, p0, Li2/p;->e:Li2/o0;

    .line 77
    .line 78
    new-instance v0, La30/b;

    .line 79
    .line 80
    const/16 v1, 0xa

    .line 81
    .line 82
    move-object v2, p0

    .line 83
    move-object v3, p1

    .line 84
    move-object/from16 v4, p3

    .line 85
    .line 86
    invoke-direct/range {v0 .. v5}, La30/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 87
    .line 88
    .line 89
    iput v11, v6, Li2/m;->f:I

    .line 90
    .line 91
    invoke-virtual {v12}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 92
    .line 93
    .line 94
    new-instance v1, Le1/z0;

    .line 95
    .line 96
    invoke-direct {v1, p2, v12, v0, v5}, Le1/z0;-><init>(Le1/w0;Li2/o0;Lay0/k;Lkotlin/coroutines/Continuation;)V

    .line 97
    .line 98
    .line 99
    invoke-static {v1, v6}, Lvy0/e0;->o(Lay0/n;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 103
    if-ne v0, v7, :cond_3

    .line 104
    .line 105
    return-object v7

    .line 106
    :cond_3
    :goto_2
    invoke-virtual {p0, v5}, Li2/p;->h(Ljava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 110
    .line 111
    .line 112
    move-result-object v0

    .line 113
    invoke-virtual {v8}, Ll2/f1;->o()F

    .line 114
    .line 115
    .line 116
    move-result v1

    .line 117
    invoke-virtual {v0, v1}, Li2/u0;->a(F)Ljava/lang/Object;

    .line 118
    .line 119
    .line 120
    move-result-object v0

    .line 121
    if-eqz v0, :cond_6

    .line 122
    .line 123
    invoke-virtual {v8}, Ll2/f1;->o()F

    .line 124
    .line 125
    .line 126
    move-result v1

    .line 127
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 128
    .line 129
    .line 130
    move-result-object v3

    .line 131
    invoke-virtual {v3, v0}, Li2/u0;->d(Ljava/lang/Object;)F

    .line 132
    .line 133
    .line 134
    move-result v3

    .line 135
    sub-float/2addr v1, v3

    .line 136
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 137
    .line 138
    .line 139
    move-result v1

    .line 140
    cmpg-float v1, v1, v10

    .line 141
    .line 142
    if-gtz v1, :cond_6

    .line 143
    .line 144
    invoke-interface {v9, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    check-cast v1, Ljava/lang/Boolean;

    .line 149
    .line 150
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 151
    .line 152
    .line 153
    move-result v1

    .line 154
    if-eqz v1, :cond_6

    .line 155
    .line 156
    invoke-virtual {p0, v0}, Li2/p;->g(Ljava/lang/Object;)V

    .line 157
    .line 158
    .line 159
    goto :goto_4

    .line 160
    :goto_3
    invoke-virtual {p0, v5}, Li2/p;->h(Ljava/lang/Object;)V

    .line 161
    .line 162
    .line 163
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 164
    .line 165
    .line 166
    move-result-object v1

    .line 167
    invoke-virtual {v8}, Ll2/f1;->o()F

    .line 168
    .line 169
    .line 170
    move-result v3

    .line 171
    invoke-virtual {v1, v3}, Li2/u0;->a(F)Ljava/lang/Object;

    .line 172
    .line 173
    .line 174
    move-result-object v1

    .line 175
    if-eqz v1, :cond_4

    .line 176
    .line 177
    invoke-virtual {v8}, Ll2/f1;->o()F

    .line 178
    .line 179
    .line 180
    move-result v3

    .line 181
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 182
    .line 183
    .line 184
    move-result-object v4

    .line 185
    invoke-virtual {v4, v1}, Li2/u0;->d(Ljava/lang/Object;)F

    .line 186
    .line 187
    .line 188
    move-result v4

    .line 189
    sub-float/2addr v3, v4

    .line 190
    invoke-static {v3}, Ljava/lang/Math;->abs(F)F

    .line 191
    .line 192
    .line 193
    move-result v3

    .line 194
    cmpg-float v3, v3, v10

    .line 195
    .line 196
    if-gtz v3, :cond_4

    .line 197
    .line 198
    invoke-interface {v9, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 199
    .line 200
    .line 201
    move-result-object v3

    .line 202
    check-cast v3, Ljava/lang/Boolean;

    .line 203
    .line 204
    invoke-virtual {v3}, Ljava/lang/Boolean;->booleanValue()Z

    .line 205
    .line 206
    .line 207
    move-result v3

    .line 208
    if-eqz v3, :cond_4

    .line 209
    .line 210
    invoke-virtual {p0, v1}, Li2/p;->g(Ljava/lang/Object;)V

    .line 211
    .line 212
    .line 213
    :cond_4
    throw v0

    .line 214
    :cond_5
    invoke-virtual/range {p0 .. p1}, Li2/p;->g(Ljava/lang/Object;)V

    .line 215
    .line 216
    .line 217
    :cond_6
    :goto_4
    sget-object v0, Llx0/b0;->a:Llx0/b0;

    .line 218
    .line 219
    return-object v0
.end method

.method public final c(FFLjava/lang/Object;)Ljava/lang/Object;
    .locals 5

    .line 1
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0, p3}, Li2/u0;->d(Ljava/lang/Object;)F

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    iget-object v2, p0, Li2/p;->b:Lay0/a;

    .line 10
    .line 11
    invoke-interface {v2}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v2

    .line 15
    check-cast v2, Ljava/lang/Number;

    .line 16
    .line 17
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 18
    .line 19
    .line 20
    move-result v2

    .line 21
    cmpg-float v3, v1, p1

    .line 22
    .line 23
    if-nez v3, :cond_0

    .line 24
    .line 25
    goto/16 :goto_0

    .line 26
    .line 27
    :cond_0
    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    .line 28
    .line 29
    .line 30
    move-result v4

    .line 31
    if-eqz v4, :cond_1

    .line 32
    .line 33
    goto/16 :goto_0

    .line 34
    .line 35
    :cond_1
    iget-object p0, p0, Li2/p;->a:Lh2/n8;

    .line 36
    .line 37
    if-gez v3, :cond_4

    .line 38
    .line 39
    cmpl-float p2, p2, v2

    .line 40
    .line 41
    const/4 v2, 0x1

    .line 42
    if-ltz p2, :cond_2

    .line 43
    .line 44
    invoke-virtual {v0, p1, v2}, Li2/u0;->b(FZ)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 49
    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_2
    invoke-virtual {v0, p1, v2}, Li2/u0;->b(FZ)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    invoke-virtual {v0, p2}, Li2/u0;->d(Ljava/lang/Object;)F

    .line 60
    .line 61
    .line 62
    move-result v0

    .line 63
    sub-float/2addr v0, v1

    .line 64
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 65
    .line 66
    .line 67
    move-result v0

    .line 68
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 69
    .line 70
    .line 71
    move-result-object v0

    .line 72
    invoke-virtual {p0, v0}, Lh2/n8;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    check-cast p0, Ljava/lang/Number;

    .line 77
    .line 78
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 83
    .line 84
    .line 85
    move-result p0

    .line 86
    add-float/2addr p0, v1

    .line 87
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 88
    .line 89
    .line 90
    move-result p0

    .line 91
    cmpg-float p0, p1, p0

    .line 92
    .line 93
    if-gez p0, :cond_3

    .line 94
    .line 95
    goto :goto_0

    .line 96
    :cond_3
    return-object p2

    .line 97
    :cond_4
    neg-float v2, v2

    .line 98
    cmpg-float p2, p2, v2

    .line 99
    .line 100
    const/4 v2, 0x0

    .line 101
    if-gtz p2, :cond_5

    .line 102
    .line 103
    invoke-virtual {v0, p1, v2}, Li2/u0;->b(FZ)Ljava/lang/Object;

    .line 104
    .line 105
    .line 106
    move-result-object p0

    .line 107
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 108
    .line 109
    .line 110
    return-object p0

    .line 111
    :cond_5
    invoke-virtual {v0, p1, v2}, Li2/u0;->b(FZ)Ljava/lang/Object;

    .line 112
    .line 113
    .line 114
    move-result-object p2

    .line 115
    invoke-static {p2}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    invoke-virtual {v0, p2}, Li2/u0;->d(Ljava/lang/Object;)F

    .line 119
    .line 120
    .line 121
    move-result v0

    .line 122
    sub-float v0, v1, v0

    .line 123
    .line 124
    invoke-static {v0}, Ljava/lang/Math;->abs(F)F

    .line 125
    .line 126
    .line 127
    move-result v0

    .line 128
    invoke-static {v0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 129
    .line 130
    .line 131
    move-result-object v0

    .line 132
    invoke-virtual {p0, v0}, Lh2/n8;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    check-cast p0, Ljava/lang/Number;

    .line 137
    .line 138
    invoke-virtual {p0}, Ljava/lang/Number;->floatValue()F

    .line 139
    .line 140
    .line 141
    move-result p0

    .line 142
    invoke-static {p0}, Ljava/lang/Math;->abs(F)F

    .line 143
    .line 144
    .line 145
    move-result p0

    .line 146
    sub-float/2addr v1, p0

    .line 147
    invoke-static {v1}, Ljava/lang/Math;->abs(F)F

    .line 148
    .line 149
    .line 150
    move-result p0

    .line 151
    const/4 v0, 0x0

    .line 152
    cmpg-float v0, p1, v0

    .line 153
    .line 154
    if-gez v0, :cond_6

    .line 155
    .line 156
    invoke-static {p1}, Ljava/lang/Math;->abs(F)F

    .line 157
    .line 158
    .line 159
    move-result p1

    .line 160
    cmpg-float p0, p1, p0

    .line 161
    .line 162
    if-gez p0, :cond_7

    .line 163
    .line 164
    goto :goto_0

    .line 165
    :cond_6
    cmpl-float p0, p1, p0

    .line 166
    .line 167
    if-lez p0, :cond_7

    .line 168
    .line 169
    :goto_0
    return-object p3

    .line 170
    :cond_7
    return-object p2
.end method

.method public final d()Li2/u0;
    .locals 0

    .line 1
    iget-object p0, p0, Li2/p;->m:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Li2/u0;

    .line 8
    .line 9
    return-object p0
.end method

.method public final e(F)F
    .locals 3

    .line 1
    iget-object v0, p0, Li2/p;->j:Ll2/f1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-static {v1}, Ljava/lang/Float;->isNaN(F)Z

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    if-eqz v1, :cond_0

    .line 12
    .line 13
    const/4 v0, 0x0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    invoke-virtual {v0}, Ll2/f1;->o()F

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    :goto_0
    add-float/2addr v0, p1

    .line 20
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    invoke-virtual {p1}, Li2/u0;->c()F

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    invoke-virtual {p0}, Li2/p;->d()Li2/u0;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    iget-object p0, p0, Li2/u0;->a:Ljava/util/Map;

    .line 33
    .line 34
    invoke-interface {p0}, Ljava/util/Map;->values()Ljava/util/Collection;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    check-cast p0, Ljava/lang/Iterable;

    .line 39
    .line 40
    const-string v1, "<this>"

    .line 41
    .line 42
    invoke-static {p0, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 43
    .line 44
    .line 45
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    if-nez v1, :cond_1

    .line 54
    .line 55
    const/4 p0, 0x0

    .line 56
    goto :goto_2

    .line 57
    :cond_1
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    check-cast v1, Ljava/lang/Number;

    .line 62
    .line 63
    invoke-virtual {v1}, Ljava/lang/Number;->floatValue()F

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    :goto_1
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-eqz v2, :cond_2

    .line 72
    .line 73
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 74
    .line 75
    .line 76
    move-result-object v2

    .line 77
    check-cast v2, Ljava/lang/Number;

    .line 78
    .line 79
    invoke-virtual {v2}, Ljava/lang/Number;->floatValue()F

    .line 80
    .line 81
    .line 82
    move-result v2

    .line 83
    invoke-static {v1, v2}, Ljava/lang/Math;->max(FF)F

    .line 84
    .line 85
    .line 86
    move-result v1

    .line 87
    goto :goto_1

    .line 88
    :cond_2
    invoke-static {v1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 89
    .line 90
    .line 91
    move-result-object p0

    .line 92
    :goto_2
    if-eqz p0, :cond_3

    .line 93
    .line 94
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 95
    .line 96
    .line 97
    move-result p0

    .line 98
    goto :goto_3

    .line 99
    :cond_3
    const/high16 p0, 0x7fc00000    # Float.NaN

    .line 100
    .line 101
    :goto_3
    invoke-static {v0, p1, p0}, Lkp/r9;->d(FFF)F

    .line 102
    .line 103
    .line 104
    move-result p0

    .line 105
    return p0
.end method

.method public final f()F
    .locals 1

    .line 1
    iget-object p0, p0, Li2/p;->j:Ll2/f1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    invoke-static {v0}, Ljava/lang/Float;->isNaN(F)Z

    .line 8
    .line 9
    .line 10
    move-result v0

    .line 11
    if-nez v0, :cond_0

    .line 12
    .line 13
    invoke-virtual {p0}, Ll2/f1;->o()F

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0

    .line 18
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 19
    .line 20
    const-string v0, "The offset was read before being initialized. Did you access the offset in a phase before layout, like effects or composition?"

    .line 21
    .line 22
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    throw p0
.end method

.method public final g(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Li2/p;->g:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final h(Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Li2/p;->l:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public final i(FLrx0/i;)Ljava/lang/Object;
    .locals 5

    .line 1
    iget-object v0, p0, Li2/p;->g:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {v0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    invoke-virtual {p0}, Li2/p;->f()F

    .line 8
    .line 9
    .line 10
    move-result v1

    .line 11
    invoke-virtual {p0, v1, p1, v0}, Li2/p;->c(FFLjava/lang/Object;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    iget-object v2, p0, Li2/p;->d:Lay0/k;

    .line 16
    .line 17
    invoke-interface {v2, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object v2

    .line 21
    check-cast v2, Ljava/lang/Boolean;

    .line 22
    .line 23
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    const/4 v3, 0x0

    .line 28
    sget-object v4, Llx0/b0;->a:Llx0/b0;

    .line 29
    .line 30
    if-eqz v2, :cond_1

    .line 31
    .line 32
    new-instance v0, Li2/h;

    .line 33
    .line 34
    invoke-direct {v0, p0, p1, v3}, Li2/h;-><init>(Li2/p;FLkotlin/coroutines/Continuation;)V

    .line 35
    .line 36
    .line 37
    sget-object p1, Le1/w0;->d:Le1/w0;

    .line 38
    .line 39
    invoke-virtual {p0, v1, p1, v0, p2}, Li2/p;->b(Ljava/lang/Object;Le1/w0;Lay0/p;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 44
    .line 45
    if-ne p0, p1, :cond_0

    .line 46
    .line 47
    goto :goto_0

    .line 48
    :cond_0
    move-object p0, v4

    .line 49
    :goto_0
    if-ne p0, p1, :cond_3

    .line 50
    .line 51
    return-object p0

    .line 52
    :cond_1
    new-instance v1, Li2/h;

    .line 53
    .line 54
    invoke-direct {v1, p0, p1, v3}, Li2/h;-><init>(Li2/p;FLkotlin/coroutines/Continuation;)V

    .line 55
    .line 56
    .line 57
    sget-object p1, Le1/w0;->d:Le1/w0;

    .line 58
    .line 59
    invoke-virtual {p0, v0, p1, v1, p2}, Li2/p;->b(Ljava/lang/Object;Le1/w0;Lay0/p;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 60
    .line 61
    .line 62
    move-result-object p0

    .line 63
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 64
    .line 65
    if-ne p0, p1, :cond_2

    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_2
    move-object p0, v4

    .line 69
    :goto_1
    if-ne p0, p1, :cond_3

    .line 70
    .line 71
    return-object p0

    .line 72
    :cond_3
    return-object v4
.end method
