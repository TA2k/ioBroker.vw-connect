.class public final Lfz/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/c;


# instance fields
.field public final a:Lfz/u;


# direct methods
.method public constructor <init>(Lfz/u;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lfz/j;->a:Lfz/u;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final bridge synthetic a(Ljava/lang/Object;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 0

    .line 1
    check-cast p1, Llx0/b0;

    .line 2
    .line 3
    invoke-virtual {p0, p2}, Lfz/j;->b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final b(Lkotlin/coroutines/Continuation;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p1, Lfz/h;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lfz/h;

    .line 7
    .line 8
    iget v1, v0, Lfz/h;->f:I

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
    iput v1, v0, Lfz/h;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lfz/h;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lfz/h;-><init>(Lfz/j;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lfz/h;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lfz/h;->f:I

    .line 30
    .line 31
    iget-object v3, p0, Lfz/j;->a:Lfz/u;

    .line 32
    .line 33
    const/4 v4, 0x3

    .line 34
    const/4 v5, 0x2

    .line 35
    const/4 v6, 0x1

    .line 36
    if-eqz v2, :cond_4

    .line 37
    .line 38
    if-eq v2, v6, :cond_3

    .line 39
    .line 40
    if-eq v2, v5, :cond_2

    .line 41
    .line 42
    if-ne v2, v4, :cond_1

    .line 43
    .line 44
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    return-object p1

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
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 57
    .line 58
    .line 59
    goto :goto_2

    .line 60
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 61
    .line 62
    .line 63
    goto :goto_1

    .line 64
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 65
    .line 66
    .line 67
    iput v6, v0, Lfz/h;->f:I

    .line 68
    .line 69
    move-object p1, v3

    .line 70
    check-cast p1, Ldz/g;

    .line 71
    .line 72
    invoke-virtual {p1, v0}, Ldz/g;->d(Lrx0/c;)Ljava/lang/Object;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    if-ne p1, v1, :cond_5

    .line 77
    .line 78
    goto :goto_3

    .line 79
    :cond_5
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 80
    .line 81
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 82
    .line 83
    .line 84
    move-result p1

    .line 85
    if-nez p1, :cond_8

    .line 86
    .line 87
    iput v5, v0, Lfz/h;->f:I

    .line 88
    .line 89
    check-cast v3, Ldz/g;

    .line 90
    .line 91
    invoke-virtual {v3, v0}, Ldz/g;->e(Lrx0/c;)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object p1

    .line 95
    if-ne p1, v1, :cond_6

    .line 96
    .line 97
    goto :goto_3

    .line 98
    :cond_6
    :goto_2
    check-cast p1, Ljava/lang/Boolean;

    .line 99
    .line 100
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 101
    .line 102
    .line 103
    move-result p1

    .line 104
    if-nez p1, :cond_8

    .line 105
    .line 106
    iput v4, v0, Lfz/h;->f:I

    .line 107
    .line 108
    invoke-virtual {p0, v0}, Lfz/j;->c(Lrx0/c;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    move-result-object p0

    .line 112
    if-ne p0, v1, :cond_7

    .line 113
    .line 114
    :goto_3
    return-object v1

    .line 115
    :cond_7
    return-object p0

    .line 116
    :cond_8
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 117
    .line 118
    return-object p0
.end method

.method public final c(Lrx0/c;)Ljava/lang/Object;
    .locals 9

    .line 1
    instance-of v0, p1, Lfz/i;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lfz/i;

    .line 7
    .line 8
    iget v1, v0, Lfz/i;->g:I

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
    iput v1, v0, Lfz/i;->g:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lfz/i;

    .line 21
    .line 22
    invoke-direct {v0, p0, p1}, Lfz/i;-><init>(Lfz/j;Lrx0/c;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lfz/i;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lfz/i;->g:I

    .line 30
    .line 31
    const/4 v3, 0x3

    .line 32
    const/4 v4, 0x2

    .line 33
    iget-object p0, p0, Lfz/j;->a:Lfz/u;

    .line 34
    .line 35
    const/4 v5, 0x1

    .line 36
    if-eqz v2, :cond_4

    .line 37
    .line 38
    if-eq v2, v5, :cond_3

    .line 39
    .line 40
    if-eq v2, v4, :cond_2

    .line 41
    .line 42
    if-ne v2, v3, :cond_1

    .line 43
    .line 44
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 45
    .line 46
    .line 47
    goto/16 :goto_8

    .line 48
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
    iget-boolean v2, v0, Lfz/i;->d:Z

    .line 58
    .line 59
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 60
    .line 61
    .line 62
    goto :goto_2

    .line 63
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 64
    .line 65
    .line 66
    goto :goto_1

    .line 67
    :cond_4
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 68
    .line 69
    .line 70
    iput v5, v0, Lfz/i;->g:I

    .line 71
    .line 72
    move-object p1, p0

    .line 73
    check-cast p1, Ldz/g;

    .line 74
    .line 75
    invoke-virtual {p1, v0}, Ldz/g;->c(Lrx0/c;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object p1

    .line 79
    if-ne p1, v1, :cond_5

    .line 80
    .line 81
    goto :goto_7

    .line 82
    :cond_5
    :goto_1
    check-cast p1, Ljava/lang/Boolean;

    .line 83
    .line 84
    invoke-virtual {p1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    if-nez v2, :cond_d

    .line 89
    .line 90
    iput-boolean v2, v0, Lfz/i;->d:Z

    .line 91
    .line 92
    iput v4, v0, Lfz/i;->g:I

    .line 93
    .line 94
    move-object p1, p0

    .line 95
    check-cast p1, Ldz/g;

    .line 96
    .line 97
    iget-object p1, p1, Ldz/g;->a:Lve0/u;

    .line 98
    .line 99
    const-string v4, "PREF_RATING_ADDED_VERSION"

    .line 100
    .line 101
    invoke-virtual {p1, v4, v0}, Lve0/u;->f(Ljava/lang/String;Lrx0/c;)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object p1

    .line 105
    if-ne p1, v1, :cond_6

    .line 106
    .line 107
    goto :goto_7

    .line 108
    :cond_6
    :goto_2
    check-cast p1, Ljava/lang/String;

    .line 109
    .line 110
    const/4 v4, 0x0

    .line 111
    if-eqz p1, :cond_9

    .line 112
    .line 113
    invoke-virtual {p1}, Ljava/lang/String;->length()I

    .line 114
    .line 115
    .line 116
    move-result v6

    .line 117
    move v7, v4

    .line 118
    :goto_3
    if-ge v7, v6, :cond_8

    .line 119
    .line 120
    invoke-virtual {p1, v7}, Ljava/lang/String;->charAt(I)C

    .line 121
    .line 122
    .line 123
    move-result v8

    .line 124
    int-to-char v8, v8

    .line 125
    invoke-static {v8}, Ljava/lang/Character;->isDigit(C)Z

    .line 126
    .line 127
    .line 128
    move-result v8

    .line 129
    if-nez v8, :cond_7

    .line 130
    .line 131
    invoke-virtual {p1, v4, v7}, Ljava/lang/String;->substring(II)Ljava/lang/String;

    .line 132
    .line 133
    .line 134
    move-result-object p1

    .line 135
    const-string v6, "substring(...)"

    .line 136
    .line 137
    invoke-static {p1, v6}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 138
    .line 139
    .line 140
    goto :goto_4

    .line 141
    :cond_7
    add-int/lit8 v7, v7, 0x1

    .line 142
    .line 143
    goto :goto_3

    .line 144
    :cond_8
    :goto_4
    invoke-static {p1}, Lly0/w;->y(Ljava/lang/String;)Ljava/lang/Integer;

    .line 145
    .line 146
    .line 147
    move-result-object p1

    .line 148
    if-eqz p1, :cond_9

    .line 149
    .line 150
    invoke-virtual {p1}, Ljava/lang/Integer;->intValue()I

    .line 151
    .line 152
    .line 153
    move-result p1

    .line 154
    goto :goto_5

    .line 155
    :cond_9
    move p1, v4

    .line 156
    :goto_5
    if-eqz p1, :cond_b

    .line 157
    .line 158
    iput-boolean v2, v0, Lfz/i;->d:Z

    .line 159
    .line 160
    iput v3, v0, Lfz/i;->g:I

    .line 161
    .line 162
    check-cast p0, Ldz/g;

    .line 163
    .line 164
    iget-object p0, p0, Ldz/g;->a:Lve0/u;

    .line 165
    .line 166
    const-string p1, "PREF_EVER_RATED"

    .line 167
    .line 168
    invoke-virtual {p0, v5, p1, v0}, Lve0/u;->l(ZLjava/lang/String;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 169
    .line 170
    .line 171
    move-result-object p0

    .line 172
    sget-object p1, Lqx0/a;->d:Lqx0/a;

    .line 173
    .line 174
    if-ne p0, p1, :cond_a

    .line 175
    .line 176
    goto :goto_6

    .line 177
    :cond_a
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 178
    .line 179
    :goto_6
    if-ne p0, v1, :cond_c

    .line 180
    .line 181
    :goto_7
    return-object v1

    .line 182
    :cond_b
    move v5, v4

    .line 183
    :cond_c
    :goto_8
    invoke-static {v5}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 184
    .line 185
    .line 186
    move-result-object p0

    .line 187
    return-object p0

    .line 188
    :cond_d
    sget-object p0, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 189
    .line 190
    return-object p0
.end method
