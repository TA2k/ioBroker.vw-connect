.class public final Lc80/g;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lzd0/a;

.field public final i:Lwq0/k;

.field public final j:Lwq0/m;

.field public final k:Lwq0/y;

.field public final l:Lij0/a;


# direct methods
.method public constructor <init>(Lzd0/a;Lwq0/k;Lwq0/m;Lwq0/y;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lc80/c;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    const/4 v2, 0x7

    .line 5
    invoke-direct {v0, v1, v1, v2}, Lc80/c;-><init>(Lc80/b;Lc80/a;I)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lc80/g;->h:Lzd0/a;

    .line 12
    .line 13
    iput-object p2, p0, Lc80/g;->i:Lwq0/k;

    .line 14
    .line 15
    iput-object p3, p0, Lc80/g;->j:Lwq0/m;

    .line 16
    .line 17
    iput-object p4, p0, Lc80/g;->k:Lwq0/y;

    .line 18
    .line 19
    iput-object p5, p0, Lc80/g;->l:Lij0/a;

    .line 20
    .line 21
    return-void
.end method

.method public static final h(Lc80/g;Lyq0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 10

    .line 1
    iget-object v0, p0, Lc80/g;->l:Lij0/a;

    .line 2
    .line 3
    instance-of v1, p2, Lc80/f;

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    move-object v1, p2

    .line 8
    check-cast v1, Lc80/f;

    .line 9
    .line 10
    iget v2, v1, Lc80/f;->h:I

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
    iput v2, v1, Lc80/f;->h:I

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v1, Lc80/f;

    .line 23
    .line 24
    invoke-direct {v1, p0, p2}, Lc80/f;-><init>(Lc80/g;Lrx0/c;)V

    .line 25
    .line 26
    .line 27
    :goto_0
    iget-object p2, v1, Lc80/f;->f:Ljava/lang/Object;

    .line 28
    .line 29
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 30
    .line 31
    iget v3, v1, Lc80/f;->h:I

    .line 32
    .line 33
    const/4 v4, 0x2

    .line 34
    const/4 v5, -0x1

    .line 35
    const/4 v6, 0x0

    .line 36
    const/4 v7, 0x1

    .line 37
    if-eqz v3, :cond_2

    .line 38
    .line 39
    if-ne v3, v7, :cond_1

    .line 40
    .line 41
    iget-object p0, v1, Lc80/f;->e:Ljava/lang/String;

    .line 42
    .line 43
    iget-object p1, v1, Lc80/f;->d:Lyq0/n;

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
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    if-nez p1, :cond_3

    .line 61
    .line 62
    move p2, v5

    .line 63
    goto :goto_1

    .line 64
    :cond_3
    sget-object p2, Lc80/d;->a:[I

    .line 65
    .line 66
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 67
    .line 68
    .line 69
    move-result v3

    .line 70
    aget p2, p2, v3

    .line 71
    .line 72
    :goto_1
    if-eq p2, v7, :cond_5

    .line 73
    .line 74
    if-eq p2, v4, :cond_4

    .line 75
    .line 76
    new-array p2, v6, [Ljava/lang/Object;

    .line 77
    .line 78
    move-object v3, v0

    .line 79
    check-cast v3, Ljj0/f;

    .line 80
    .line 81
    const v8, 0x7f121231

    .line 82
    .line 83
    .line 84
    invoke-virtual {v3, v8, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 85
    .line 86
    .line 87
    move-result-object p2

    .line 88
    goto :goto_2

    .line 89
    :cond_4
    new-array p2, v6, [Ljava/lang/Object;

    .line 90
    .line 91
    move-object v3, v0

    .line 92
    check-cast v3, Ljj0/f;

    .line 93
    .line 94
    const v8, 0x7f121233

    .line 95
    .line 96
    .line 97
    invoke-virtual {v3, v8, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p2

    .line 101
    goto :goto_2

    .line 102
    :cond_5
    new-array p2, v6, [Ljava/lang/Object;

    .line 103
    .line 104
    move-object v3, v0

    .line 105
    check-cast v3, Ljj0/f;

    .line 106
    .line 107
    const v8, 0x7f12124a

    .line 108
    .line 109
    .line 110
    invoke-virtual {v3, v8, p2}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p2

    .line 114
    :goto_2
    iput-object p1, v1, Lc80/f;->d:Lyq0/n;

    .line 115
    .line 116
    iput-object p2, v1, Lc80/f;->e:Ljava/lang/String;

    .line 117
    .line 118
    iput v7, v1, Lc80/f;->h:I

    .line 119
    .line 120
    invoke-virtual {p0, p1, v1}, Lc80/g;->j(Lyq0/n;Lrx0/c;)Ljava/lang/Object;

    .line 121
    .line 122
    .line 123
    move-result-object p0

    .line 124
    if-ne p0, v2, :cond_6

    .line 125
    .line 126
    return-object v2

    .line 127
    :cond_6
    move-object v9, p2

    .line 128
    move-object p2, p0

    .line 129
    move-object p0, v9

    .line 130
    :goto_3
    check-cast p2, Ljava/lang/String;

    .line 131
    .line 132
    if-nez p1, :cond_7

    .line 133
    .line 134
    goto :goto_4

    .line 135
    :cond_7
    sget-object v1, Lc80/d;->a:[I

    .line 136
    .line 137
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 138
    .line 139
    .line 140
    move-result v2

    .line 141
    aget v5, v1, v2

    .line 142
    .line 143
    :goto_4
    if-ne v5, v4, :cond_8

    .line 144
    .line 145
    new-array v1, v6, [Ljava/lang/Object;

    .line 146
    .line 147
    check-cast v0, Ljj0/f;

    .line 148
    .line 149
    const v2, 0x7f121237

    .line 150
    .line 151
    .line 152
    invoke-virtual {v0, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 153
    .line 154
    .line 155
    move-result-object v0

    .line 156
    goto :goto_5

    .line 157
    :cond_8
    new-array v1, v6, [Ljava/lang/Object;

    .line 158
    .line 159
    check-cast v0, Ljj0/f;

    .line 160
    .line 161
    const v2, 0x7f120389

    .line 162
    .line 163
    .line 164
    invoke-virtual {v0, v2, v1}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 165
    .line 166
    .line 167
    move-result-object v0

    .line 168
    :goto_5
    new-instance v1, Lc80/b;

    .line 169
    .line 170
    invoke-direct {v1, p0, p2, v0}, Lc80/b;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V

    .line 171
    .line 172
    .line 173
    sget-object p0, Lyq0/n;->d:Lyq0/n;

    .line 174
    .line 175
    if-eq p1, p0, :cond_9

    .line 176
    .line 177
    move v6, v7

    .line 178
    :cond_9
    if-eqz v6, :cond_a

    .line 179
    .line 180
    return-object v1

    .line 181
    :cond_a
    const/4 p0, 0x0

    .line 182
    return-object p0
.end method


# virtual methods
.method public final j(Lyq0/n;Lrx0/c;)Ljava/lang/Object;
    .locals 6

    .line 1
    instance-of v0, p2, Lc80/e;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p2

    .line 6
    check-cast v0, Lc80/e;

    .line 7
    .line 8
    iget v1, v0, Lc80/e;->f:I

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
    iput v1, v0, Lc80/e;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lc80/e;

    .line 21
    .line 22
    invoke-direct {v0, p0, p2}, Lc80/e;-><init>(Lc80/g;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, Lc80/e;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lc80/e;->f:I

    .line 30
    .line 31
    const/4 v3, 0x1

    .line 32
    const/4 v4, 0x0

    .line 33
    iget-object v5, p0, Lc80/g;->l:Lij0/a;

    .line 34
    .line 35
    if-eqz v2, :cond_2

    .line 36
    .line 37
    if-ne v2, v3, :cond_1

    .line 38
    .line 39
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    goto :goto_2

    .line 43
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0

    .line 51
    :cond_2
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 52
    .line 53
    .line 54
    if-nez p1, :cond_3

    .line 55
    .line 56
    const/4 p1, -0x1

    .line 57
    goto :goto_1

    .line 58
    :cond_3
    sget-object p2, Lc80/d;->a:[I

    .line 59
    .line 60
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 61
    .line 62
    .line 63
    move-result p1

    .line 64
    aget p1, p2, p1

    .line 65
    .line 66
    :goto_1
    if-eq p1, v3, :cond_5

    .line 67
    .line 68
    const/4 p0, 0x2

    .line 69
    if-eq p1, p0, :cond_4

    .line 70
    .line 71
    new-array p0, v4, [Ljava/lang/Object;

    .line 72
    .line 73
    check-cast v5, Ljj0/f;

    .line 74
    .line 75
    const p1, 0x7f121230

    .line 76
    .line 77
    .line 78
    invoke-virtual {v5, p1, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0

    .line 83
    :cond_4
    new-array p0, v4, [Ljava/lang/Object;

    .line 84
    .line 85
    check-cast v5, Ljj0/f;

    .line 86
    .line 87
    const p1, 0x7f121232

    .line 88
    .line 89
    .line 90
    invoke-virtual {v5, p1, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 91
    .line 92
    .line 93
    move-result-object p0

    .line 94
    return-object p0

    .line 95
    :cond_5
    iput v3, v0, Lc80/e;->f:I

    .line 96
    .line 97
    iget-object p0, p0, Lc80/g;->j:Lwq0/m;

    .line 98
    .line 99
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 100
    .line 101
    .line 102
    iget-object p0, p0, Lwq0/m;->a:Lwq0/m0;

    .line 103
    .line 104
    check-cast p0, Ltq0/i;

    .line 105
    .line 106
    iget-object p0, p0, Ltq0/i;->a:Lve0/u;

    .line 107
    .line 108
    const-string p1, "IS_BIOMETRIC_RESET"

    .line 109
    .line 110
    invoke-virtual {p0, v3, p1, v0}, Lve0/u;->d(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 111
    .line 112
    .line 113
    move-result-object p2

    .line 114
    if-ne p2, v1, :cond_6

    .line 115
    .line 116
    return-object v1

    .line 117
    :cond_6
    :goto_2
    check-cast p2, Ljava/lang/Boolean;

    .line 118
    .line 119
    invoke-virtual {p2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 120
    .line 121
    .line 122
    move-result p0

    .line 123
    const-string p1, "\n\n"

    .line 124
    .line 125
    const p2, 0x7f121247

    .line 126
    .line 127
    .line 128
    if-eqz p0, :cond_7

    .line 129
    .line 130
    new-array p0, v4, [Ljava/lang/Object;

    .line 131
    .line 132
    check-cast v5, Ljj0/f;

    .line 133
    .line 134
    invoke-virtual {v5, p2, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    const p2, 0x7f121249

    .line 139
    .line 140
    .line 141
    new-array v0, v4, [Ljava/lang/Object;

    .line 142
    .line 143
    invoke-virtual {v5, p2, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 144
    .line 145
    .line 146
    move-result-object p2

    .line 147
    invoke-static {p0, p1, p2}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 148
    .line 149
    .line 150
    move-result-object p0

    .line 151
    return-object p0

    .line 152
    :cond_7
    new-array p0, v4, [Ljava/lang/Object;

    .line 153
    .line 154
    check-cast v5, Ljj0/f;

    .line 155
    .line 156
    invoke-virtual {v5, p2, p0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    const p2, 0x7f121248

    .line 161
    .line 162
    .line 163
    new-array v0, v4, [Ljava/lang/Object;

    .line 164
    .line 165
    invoke-virtual {v5, p2, v0}, Ljj0/f;->c(I[Ljava/lang/Object;)Ljava/lang/String;

    .line 166
    .line 167
    .line 168
    move-result-object p2

    .line 169
    invoke-static {p0, p1, p2}, Lf2/m0;->i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    return-object p0
.end method
