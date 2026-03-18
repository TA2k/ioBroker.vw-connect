.class public final Lwi0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lwi0/i;

.field public final b:Lui0/g;

.field public final c:Lzd0/a;

.field public final d:Lgb0/d;


# direct methods
.method public constructor <init>(Lwi0/i;Lui0/g;Lzd0/a;Lgb0/d;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lwi0/n;->a:Lwi0/i;

    .line 5
    .line 6
    iput-object p2, p0, Lwi0/n;->b:Lui0/g;

    .line 7
    .line 8
    iput-object p3, p0, Lwi0/n;->c:Lzd0/a;

    .line 9
    .line 10
    iput-object p4, p0, Lwi0/n;->d:Lgb0/d;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Lyy0/j;Lyi0/f;Lrx0/c;)Ljava/lang/Object;
    .locals 18

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v2, p2

    .line 6
    .line 7
    move-object/from16 v3, p3

    .line 8
    .line 9
    instance-of v4, v3, Lwi0/k;

    .line 10
    .line 11
    if-eqz v4, :cond_0

    .line 12
    .line 13
    move-object v4, v3

    .line 14
    check-cast v4, Lwi0/k;

    .line 15
    .line 16
    iget v5, v4, Lwi0/k;->h:I

    .line 17
    .line 18
    const/high16 v6, -0x80000000

    .line 19
    .line 20
    and-int v7, v5, v6

    .line 21
    .line 22
    if-eqz v7, :cond_0

    .line 23
    .line 24
    sub-int/2addr v5, v6

    .line 25
    iput v5, v4, Lwi0/k;->h:I

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :cond_0
    new-instance v4, Lwi0/k;

    .line 29
    .line 30
    invoke-direct {v4, v0, v3}, Lwi0/k;-><init>(Lwi0/n;Lrx0/c;)V

    .line 31
    .line 32
    .line 33
    :goto_0
    iget-object v3, v4, Lwi0/k;->f:Ljava/lang/Object;

    .line 34
    .line 35
    sget-object v5, Lqx0/a;->d:Lqx0/a;

    .line 36
    .line 37
    iget v6, v4, Lwi0/k;->h:I

    .line 38
    .line 39
    const/4 v7, 0x3

    .line 40
    const/4 v8, 0x2

    .line 41
    const/4 v9, 0x1

    .line 42
    const/4 v10, 0x0

    .line 43
    if-eqz v6, :cond_4

    .line 44
    .line 45
    if-eq v6, v9, :cond_3

    .line 46
    .line 47
    if-eq v6, v8, :cond_2

    .line 48
    .line 49
    if-ne v6, v7, :cond_1

    .line 50
    .line 51
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    goto/16 :goto_4

    .line 55
    .line 56
    :cond_1
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 57
    .line 58
    const-string v1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 59
    .line 60
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 61
    .line 62
    .line 63
    throw v0

    .line 64
    :cond_2
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto :goto_2

    .line 68
    :cond_3
    iget-object v1, v4, Lwi0/k;->e:Lyi0/f;

    .line 69
    .line 70
    iget-object v2, v4, Lwi0/k;->d:Lyy0/j;

    .line 71
    .line 72
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 73
    .line 74
    .line 75
    move-object/from16 v17, v2

    .line 76
    .line 77
    move-object v2, v1

    .line 78
    move-object/from16 v1, v17

    .line 79
    .line 80
    goto :goto_1

    .line 81
    :cond_4
    invoke-static {v3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 82
    .line 83
    .line 84
    iget-boolean v3, v2, Lyi0/f;->a:Z

    .line 85
    .line 86
    if-nez v3, :cond_9

    .line 87
    .line 88
    new-instance v12, Lxi0/c;

    .line 89
    .line 90
    iget-object v3, v2, Lyi0/f;->b:Ljava/lang/String;

    .line 91
    .line 92
    iget-object v6, v2, Lyi0/f;->c:Ljava/lang/String;

    .line 93
    .line 94
    invoke-direct {v12, v3, v6}, Lxi0/c;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 95
    .line 96
    .line 97
    new-instance v11, Lne0/c;

    .line 98
    .line 99
    const/4 v15, 0x0

    .line 100
    const/16 v16, 0x1e

    .line 101
    .line 102
    const/4 v13, 0x0

    .line 103
    const/4 v14, 0x0

    .line 104
    invoke-direct/range {v11 .. v16}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 105
    .line 106
    .line 107
    iput-object v1, v4, Lwi0/k;->d:Lyy0/j;

    .line 108
    .line 109
    iput-object v2, v4, Lwi0/k;->e:Lyi0/f;

    .line 110
    .line 111
    iput v9, v4, Lwi0/k;->h:I

    .line 112
    .line 113
    invoke-virtual {v0, v1, v11, v4}, Lwi0/n;->b(Lyy0/j;Lne0/s;Lrx0/c;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v3

    .line 117
    if-ne v3, v5, :cond_5

    .line 118
    .line 119
    goto :goto_3

    .line 120
    :cond_5
    :goto_1
    check-cast v3, Lyi0/d;

    .line 121
    .line 122
    invoke-virtual {v3}, Ljava/lang/Enum;->ordinal()I

    .line 123
    .line 124
    .line 125
    move-result v3

    .line 126
    if-eqz v3, :cond_7

    .line 127
    .line 128
    if-ne v3, v9, :cond_6

    .line 129
    .line 130
    new-instance v12, Lxi0/a;

    .line 131
    .line 132
    const-string v1, "User declined mandatory legal documents consent"

    .line 133
    .line 134
    invoke-direct {v12, v1}, Ljava/lang/Exception;-><init>(Ljava/lang/String;)V

    .line 135
    .line 136
    .line 137
    new-instance v11, Lne0/c;

    .line 138
    .line 139
    const/4 v15, 0x0

    .line 140
    const/16 v16, 0x1e

    .line 141
    .line 142
    const/4 v13, 0x0

    .line 143
    const/4 v14, 0x0

    .line 144
    invoke-direct/range {v11 .. v16}, Lne0/c;-><init>(Ljava/lang/Throwable;Lne0/c;Lne0/a;Lne0/b;I)V

    .line 145
    .line 146
    .line 147
    iget-object v0, v0, Lwi0/n;->c:Lzd0/a;

    .line 148
    .line 149
    invoke-virtual {v0, v11}, Lzd0/a;->a(Lne0/t;)V

    .line 150
    .line 151
    .line 152
    return-object v11

    .line 153
    :cond_6
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 154
    .line 155
    const-string v1, "Unsupported legal action in this step"

    .line 156
    .line 157
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 158
    .line 159
    .line 160
    throw v0

    .line 161
    :cond_7
    iput-object v10, v4, Lwi0/k;->d:Lyy0/j;

    .line 162
    .line 163
    iput-object v10, v4, Lwi0/k;->e:Lyi0/f;

    .line 164
    .line 165
    iput v8, v4, Lwi0/k;->h:I

    .line 166
    .line 167
    invoke-virtual {v0, v1, v2, v4}, Lwi0/n;->c(Lyy0/j;Lyi0/f;Lrx0/c;)Ljava/lang/Object;

    .line 168
    .line 169
    .line 170
    move-result-object v1

    .line 171
    if-ne v1, v5, :cond_8

    .line 172
    .line 173
    goto :goto_3

    .line 174
    :cond_8
    :goto_2
    iput-object v10, v4, Lwi0/k;->d:Lyy0/j;

    .line 175
    .line 176
    iput-object v10, v4, Lwi0/k;->e:Lyi0/f;

    .line 177
    .line 178
    iput v7, v4, Lwi0/k;->h:I

    .line 179
    .line 180
    iget-object v0, v0, Lwi0/n;->d:Lgb0/d;

    .line 181
    .line 182
    invoke-virtual {v0, v4}, Lgb0/d;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 183
    .line 184
    .line 185
    move-result-object v0

    .line 186
    if-ne v0, v5, :cond_9

    .line 187
    .line 188
    :goto_3
    return-object v5

    .line 189
    :cond_9
    :goto_4
    new-instance v0, Lne0/e;

    .line 190
    .line 191
    sget-object v1, Llx0/b0;->a:Llx0/b0;

    .line 192
    .line 193
    invoke-direct {v0, v1}, Lne0/e;-><init>(Ljava/lang/Object;)V

    .line 194
    .line 195
    .line 196
    return-object v0
.end method

.method public final b(Lyy0/j;Lne0/s;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p3, Lwi0/l;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lwi0/l;

    .line 7
    .line 8
    iget v1, v0, Lwi0/l;->h:I

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
    iput v1, v0, Lwi0/l;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwi0/l;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lwi0/l;-><init>(Lwi0/n;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lwi0/l;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwi0/l;->h:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_4

    .line 35
    .line 36
    if-eq v2, v5, :cond_3

    .line 37
    .line 38
    if-eq v2, v4, :cond_2

    .line 39
    .line 40
    if-ne v2, v3, :cond_1

    .line 41
    .line 42
    iget-object p0, v0, Lwi0/l;->e:Ljava/lang/Object;

    .line 43
    .line 44
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object p0

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
    iget-object p0, v0, Lwi0/l;->d:Lyy0/j;

    .line 57
    .line 58
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 59
    .line 60
    .line 61
    goto :goto_2

    .line 62
    :cond_3
    iget-object p1, v0, Lwi0/l;->d:Lyy0/j;

    .line 63
    .line 64
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    goto :goto_1

    .line 68
    :cond_4
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 69
    .line 70
    .line 71
    iput-object p1, v0, Lwi0/l;->d:Lyy0/j;

    .line 72
    .line 73
    iput v5, v0, Lwi0/l;->h:I

    .line 74
    .line 75
    invoke-interface {p1, p2, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p2

    .line 79
    if-ne p2, v1, :cond_5

    .line 80
    .line 81
    goto :goto_3

    .line 82
    :cond_5
    :goto_1
    iget-object p0, p0, Lwi0/n;->a:Lwi0/i;

    .line 83
    .line 84
    check-cast p0, Lui0/a;

    .line 85
    .line 86
    iget-object p0, p0, Lui0/a;->b:Lyy0/q1;

    .line 87
    .line 88
    iput-object p1, v0, Lwi0/l;->d:Lyy0/j;

    .line 89
    .line 90
    iput v4, v0, Lwi0/l;->h:I

    .line 91
    .line 92
    invoke-static {p0, v0}, Lyy0/u;->u(Lyy0/i;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object p3

    .line 96
    if-ne p3, v1, :cond_6

    .line 97
    .line 98
    goto :goto_3

    .line 99
    :cond_6
    move-object p0, p1

    .line 100
    :goto_2
    move-object p1, p3

    .line 101
    check-cast p1, Lyi0/d;

    .line 102
    .line 103
    const/4 p1, 0x0

    .line 104
    iput-object p1, v0, Lwi0/l;->d:Lyy0/j;

    .line 105
    .line 106
    iput-object p3, v0, Lwi0/l;->e:Ljava/lang/Object;

    .line 107
    .line 108
    iput v3, v0, Lwi0/l;->h:I

    .line 109
    .line 110
    sget-object p1, Lne0/d;->a:Lne0/d;

    .line 111
    .line 112
    invoke-interface {p0, p1, v0}, Lyy0/j;->emit(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 113
    .line 114
    .line 115
    move-result-object p0

    .line 116
    if-ne p0, v1, :cond_7

    .line 117
    .line 118
    :goto_3
    return-object v1

    .line 119
    :cond_7
    return-object p3
.end method

.method public final c(Lyy0/j;Lyi0/f;Lrx0/c;)Ljava/lang/Object;
    .locals 11

    .line 1
    instance-of v0, p3, Lwi0/m;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p3

    .line 6
    check-cast v0, Lwi0/m;

    .line 7
    .line 8
    iget v1, v0, Lwi0/m;->h:I

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
    iput v1, v0, Lwi0/m;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lwi0/m;

    .line 21
    .line 22
    invoke-direct {v0, p0, p3}, Lwi0/m;-><init>(Lwi0/n;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p3, v0, Lwi0/m;->f:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lwi0/m;->h:I

    .line 30
    .line 31
    sget-object v3, Llx0/b0;->a:Llx0/b0;

    .line 32
    .line 33
    const/4 v4, 0x3

    .line 34
    const/4 v5, 0x2

    .line 35
    const/4 v6, 0x1

    .line 36
    const/4 v7, 0x0

    .line 37
    if-eqz v2, :cond_4

    .line 38
    .line 39
    if-eq v2, v6, :cond_3

    .line 40
    .line 41
    if-eq v2, v5, :cond_2

    .line 42
    .line 43
    if-ne v2, v4, :cond_1

    .line 44
    .line 45
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    return-object v3

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
    iget-object p1, v0, Lwi0/m;->e:Lyi0/f;

    .line 58
    .line 59
    iget-object p2, v0, Lwi0/m;->d:Lyy0/j;

    .line 60
    .line 61
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_2

    .line 65
    :cond_3
    iget-object p2, v0, Lwi0/m;->e:Lyi0/f;

    .line 66
    .line 67
    iget-object p1, v0, Lwi0/m;->d:Lyy0/j;

    .line 68
    .line 69
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 70
    .line 71
    .line 72
    goto :goto_1

    .line 73
    :cond_4
    invoke-static {p3}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 74
    .line 75
    .line 76
    new-instance p3, Lyi0/c;

    .line 77
    .line 78
    invoke-direct {p3}, Ljava/lang/Object;-><init>()V

    .line 79
    .line 80
    .line 81
    iput-object p1, v0, Lwi0/m;->d:Lyy0/j;

    .line 82
    .line 83
    iput-object p2, v0, Lwi0/m;->e:Lyi0/f;

    .line 84
    .line 85
    iput v6, v0, Lwi0/m;->h:I

    .line 86
    .line 87
    iget-object v2, p0, Lwi0/n;->b:Lui0/g;

    .line 88
    .line 89
    iget-object v6, v2, Lui0/g;->a:Lxl0/f;

    .line 90
    .line 91
    new-instance v8, Llo0/b;

    .line 92
    .line 93
    const/16 v9, 0x1c

    .line 94
    .line 95
    invoke-direct {v8, v9, v2, p3, v7}, Llo0/b;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 96
    .line 97
    .line 98
    invoke-virtual {v6, v8, v0}, Lxl0/f;->i(Lay0/k;Lrx0/c;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object p3

    .line 102
    if-ne p3, v1, :cond_5

    .line 103
    .line 104
    goto :goto_3

    .line 105
    :cond_5
    :goto_1
    check-cast p3, Lne0/t;

    .line 106
    .line 107
    instance-of v2, p3, Lne0/c;

    .line 108
    .line 109
    if-eqz v2, :cond_7

    .line 110
    .line 111
    check-cast p3, Lne0/s;

    .line 112
    .line 113
    iput-object p1, v0, Lwi0/m;->d:Lyy0/j;

    .line 114
    .line 115
    iput-object p2, v0, Lwi0/m;->e:Lyi0/f;

    .line 116
    .line 117
    iput v5, v0, Lwi0/m;->h:I

    .line 118
    .line 119
    invoke-virtual {p0, p1, p3, v0}, Lwi0/n;->b(Lyy0/j;Lne0/s;Lrx0/c;)Ljava/lang/Object;

    .line 120
    .line 121
    .line 122
    move-result-object p3

    .line 123
    if-ne p3, v1, :cond_6

    .line 124
    .line 125
    goto :goto_3

    .line 126
    :cond_6
    move-object v10, p2

    .line 127
    move-object p2, p1

    .line 128
    move-object p1, v10

    .line 129
    :goto_2
    iput-object v7, v0, Lwi0/m;->d:Lyy0/j;

    .line 130
    .line 131
    iput-object v7, v0, Lwi0/m;->e:Lyi0/f;

    .line 132
    .line 133
    iput v4, v0, Lwi0/m;->h:I

    .line 134
    .line 135
    invoke-virtual {p0, p2, p1, v0}, Lwi0/n;->a(Lyy0/j;Lyi0/f;Lrx0/c;)Ljava/lang/Object;

    .line 136
    .line 137
    .line 138
    move-result-object p0

    .line 139
    if-ne p0, v1, :cond_8

    .line 140
    .line 141
    :goto_3
    return-object v1

    .line 142
    :cond_7
    instance-of p0, p3, Lne0/e;

    .line 143
    .line 144
    if-eqz p0, :cond_9

    .line 145
    .line 146
    :cond_8
    return-object v3

    .line 147
    :cond_9
    new-instance p0, La8/r0;

    .line 148
    .line 149
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 150
    .line 151
    .line 152
    throw p0
.end method

.method public final invoke()Ljava/lang/Object;
    .locals 3

    .line 1
    new-instance v0, Ltr0/e;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/16 v2, 0x19

    .line 5
    .line 6
    invoke-direct {v0, p0, v1, v2}, Ltr0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 7
    .line 8
    .line 9
    new-instance p0, Lyy0/m1;

    .line 10
    .line 11
    invoke-direct {p0, v0}, Lyy0/m1;-><init>(Lay0/n;)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method
