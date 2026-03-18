.class public abstract Lyv/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lg1/e1;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lg1/e1;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const/16 v2, 0x8

    .line 5
    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v3, v2}, Lg1/e1;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 8
    .line 9
    .line 10
    sput-object v0, Lyv/e;->a:Lg1/e1;

    .line 11
    .line 12
    return-void
.end method

.method public static final a(Lp3/i0;Lrx0/a;)Ljava/lang/Object;
    .locals 8

    .line 1
    instance-of v0, p1, Lyv/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lyv/a;

    .line 7
    .line 8
    iget v1, v0, Lyv/a;->f:I

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
    iput v1, v0, Lyv/a;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyv/a;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lyv/a;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyv/a;->f:I

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
    iget-object p0, v0, Lyv/a;->d:Lp3/i0;

    .line 37
    .line 38
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 39
    .line 40
    .line 41
    goto :goto_2

    .line 42
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 43
    .line 44
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 51
    .line 52
    .line 53
    :goto_1
    iput-object p0, v0, Lyv/a;->d:Lp3/i0;

    .line 54
    .line 55
    iput v3, v0, Lyv/a;->f:I

    .line 56
    .line 57
    sget-object p1, Lp3/l;->e:Lp3/l;

    .line 58
    .line 59
    invoke-virtual {p0, p1, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

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
    :goto_2
    check-cast p1, Lp3/k;

    .line 67
    .line 68
    iget-object v2, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 69
    .line 70
    invoke-interface {v2}, Ljava/util/List;->size()I

    .line 71
    .line 72
    .line 73
    move-result v4

    .line 74
    const/4 v5, 0x0

    .line 75
    move v6, v5

    .line 76
    :goto_3
    if-ge v6, v4, :cond_4

    .line 77
    .line 78
    invoke-interface {v2, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 79
    .line 80
    .line 81
    move-result-object v7

    .line 82
    check-cast v7, Lp3/t;

    .line 83
    .line 84
    invoke-virtual {v7}, Lp3/t;->a()V

    .line 85
    .line 86
    .line 87
    add-int/lit8 v6, v6, 0x1

    .line 88
    .line 89
    goto :goto_3

    .line 90
    :cond_4
    iget-object p1, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 91
    .line 92
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 93
    .line 94
    .line 95
    move-result v2

    .line 96
    :goto_4
    if-ge v5, v2, :cond_6

    .line 97
    .line 98
    invoke-interface {p1, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    move-result-object v4

    .line 102
    check-cast v4, Lp3/t;

    .line 103
    .line 104
    iget-boolean v4, v4, Lp3/t;->d:Z

    .line 105
    .line 106
    if-eqz v4, :cond_5

    .line 107
    .line 108
    goto :goto_1

    .line 109
    :cond_5
    add-int/lit8 v5, v5, 0x1

    .line 110
    .line 111
    goto :goto_4

    .line 112
    :cond_6
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 113
    .line 114
    return-object p0
.end method

.method public static final b(Lp3/i0;Lrx0/a;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p1, Lyv/d;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lyv/d;

    .line 7
    .line 8
    iget v1, v0, Lyv/d;->f:I

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
    iput v1, v0, Lyv/d;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lyv/d;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lyv/d;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lyv/d;->f:I

    .line 30
    .line 31
    const/4 v3, 0x2

    .line 32
    const/4 v4, 0x0

    .line 33
    const/4 v5, 0x1

    .line 34
    if-eqz v2, :cond_3

    .line 35
    .line 36
    if-eq v2, v5, :cond_2

    .line 37
    .line 38
    if-ne v2, v3, :cond_1

    .line 39
    .line 40
    iget-object p0, v0, Lyv/d;->d:Lp3/i0;

    .line 41
    .line 42
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto :goto_5

    .line 46
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 47
    .line 48
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 49
    .line 50
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 51
    .line 52
    .line 53
    throw p0

    .line 54
    :cond_2
    iget-object p0, v0, Lyv/d;->d:Lp3/i0;

    .line 55
    .line 56
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_1

    .line 60
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    :cond_4
    sget-object p1, Lp3/l;->e:Lp3/l;

    .line 64
    .line 65
    iput-object p0, v0, Lyv/d;->d:Lp3/i0;

    .line 66
    .line 67
    iput v5, v0, Lyv/d;->f:I

    .line 68
    .line 69
    invoke-virtual {p0, p1, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object p1

    .line 73
    if-ne p1, v1, :cond_5

    .line 74
    .line 75
    goto :goto_4

    .line 76
    :cond_5
    :goto_1
    check-cast p1, Lp3/k;

    .line 77
    .line 78
    iget-object p1, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 79
    .line 80
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 81
    .line 82
    .line 83
    move-result v2

    .line 84
    move v6, v4

    .line 85
    :goto_2
    if-ge v6, v2, :cond_c

    .line 86
    .line 87
    invoke-interface {p1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 88
    .line 89
    .line 90
    move-result-object v7

    .line 91
    check-cast v7, Lp3/t;

    .line 92
    .line 93
    invoke-static {v7}, Lp3/s;->c(Lp3/t;)Z

    .line 94
    .line 95
    .line 96
    move-result v7

    .line 97
    if-nez v7, :cond_b

    .line 98
    .line 99
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 100
    .line 101
    .line 102
    move-result v2

    .line 103
    move v6, v4

    .line 104
    :goto_3
    if-ge v6, v2, :cond_7

    .line 105
    .line 106
    invoke-interface {p1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v7

    .line 110
    check-cast v7, Lp3/t;

    .line 111
    .line 112
    invoke-virtual {v7}, Lp3/t;->b()Z

    .line 113
    .line 114
    .line 115
    move-result v8

    .line 116
    if-nez v8, :cond_9

    .line 117
    .line 118
    iget-object v8, p0, Lp3/i0;->i:Lp3/j0;

    .line 119
    .line 120
    iget-wide v8, v8, Lp3/j0;->B:J

    .line 121
    .line 122
    invoke-virtual {p0}, Lp3/i0;->d()J

    .line 123
    .line 124
    .line 125
    move-result-wide v10

    .line 126
    invoke-static {v7, v8, v9, v10, v11}, Lp3/s;->f(Lp3/t;JJ)Z

    .line 127
    .line 128
    .line 129
    move-result v7

    .line 130
    if-eqz v7, :cond_6

    .line 131
    .line 132
    goto :goto_7

    .line 133
    :cond_6
    add-int/lit8 v6, v6, 0x1

    .line 134
    .line 135
    goto :goto_3

    .line 136
    :cond_7
    sget-object p1, Lp3/l;->f:Lp3/l;

    .line 137
    .line 138
    iput-object p0, v0, Lyv/d;->d:Lp3/i0;

    .line 139
    .line 140
    iput v3, v0, Lyv/d;->f:I

    .line 141
    .line 142
    invoke-virtual {p0, p1, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 143
    .line 144
    .line 145
    move-result-object p1

    .line 146
    if-ne p1, v1, :cond_8

    .line 147
    .line 148
    :goto_4
    return-object v1

    .line 149
    :cond_8
    :goto_5
    check-cast p1, Lp3/k;

    .line 150
    .line 151
    iget-object p1, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 152
    .line 153
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 154
    .line 155
    .line 156
    move-result v2

    .line 157
    move v6, v4

    .line 158
    :goto_6
    if-ge v6, v2, :cond_4

    .line 159
    .line 160
    invoke-interface {p1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v7

    .line 164
    check-cast v7, Lp3/t;

    .line 165
    .line 166
    invoke-virtual {v7}, Lp3/t;->b()Z

    .line 167
    .line 168
    .line 169
    move-result v7

    .line 170
    if-eqz v7, :cond_a

    .line 171
    .line 172
    :cond_9
    :goto_7
    const/4 p0, 0x0

    .line 173
    return-object p0

    .line 174
    :cond_a
    add-int/lit8 v6, v6, 0x1

    .line 175
    .line 176
    goto :goto_6

    .line 177
    :cond_b
    add-int/lit8 v6, v6, 0x1

    .line 178
    .line 179
    goto :goto_2

    .line 180
    :cond_c
    invoke-interface {p1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 181
    .line 182
    .line 183
    move-result-object p0

    .line 184
    return-object p0
.end method
