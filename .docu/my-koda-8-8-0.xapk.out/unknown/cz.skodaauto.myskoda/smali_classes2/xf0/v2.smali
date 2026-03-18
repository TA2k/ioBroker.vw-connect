.class public abstract Lxf0/v2;
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
    const/4 v2, 0x6

    .line 5
    const/4 v3, 0x0

    .line 6
    invoke-direct {v0, v1, v3, v2}, Lg1/e1;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lxf0/v2;->a:Lg1/e1;

    .line 10
    .line 11
    return-void
.end method

.method public static final a(Lp3/i0;Lrx0/a;)Ljava/lang/Object;
    .locals 12

    .line 1
    instance-of v0, p1, Lxf0/u2;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, Lxf0/u2;

    .line 7
    .line 8
    iget v1, v0, Lxf0/u2;->f:I

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
    iput v1, v0, Lxf0/u2;->f:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, Lxf0/u2;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, Lxf0/u2;->e:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v2, v0, Lxf0/u2;->f:I

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
    iget-object p0, v0, Lxf0/u2;->d:Lp3/i0;

    .line 41
    .line 42
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    goto/16 :goto_5

    .line 46
    .line 47
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 48
    .line 49
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 50
    .line 51
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 52
    .line 53
    .line 54
    throw p0

    .line 55
    :cond_2
    iget-object p0, v0, Lxf0/u2;->d:Lp3/i0;

    .line 56
    .line 57
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 58
    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_3
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    :cond_4
    sget-object p1, Lp3/l;->d:Lp3/l;

    .line 65
    .line 66
    iput-object p0, v0, Lxf0/u2;->d:Lp3/i0;

    .line 67
    .line 68
    iput v5, v0, Lxf0/u2;->f:I

    .line 69
    .line 70
    invoke-virtual {p0, p1, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 71
    .line 72
    .line 73
    move-result-object p1

    .line 74
    if-ne p1, v1, :cond_5

    .line 75
    .line 76
    goto :goto_4

    .line 77
    :cond_5
    :goto_1
    check-cast p1, Lp3/k;

    .line 78
    .line 79
    iget-object p1, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 80
    .line 81
    move-object v2, p1

    .line 82
    check-cast v2, Ljava/util/Collection;

    .line 83
    .line 84
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 85
    .line 86
    .line 87
    move-result v2

    .line 88
    move v6, v4

    .line 89
    :goto_2
    if-ge v6, v2, :cond_c

    .line 90
    .line 91
    invoke-interface {p1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 92
    .line 93
    .line 94
    move-result-object v7

    .line 95
    check-cast v7, Lp3/t;

    .line 96
    .line 97
    invoke-static {v7}, Lp3/s;->c(Lp3/t;)Z

    .line 98
    .line 99
    .line 100
    move-result v7

    .line 101
    if-nez v7, :cond_b

    .line 102
    .line 103
    move-object v2, p1

    .line 104
    check-cast v2, Ljava/util/Collection;

    .line 105
    .line 106
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 107
    .line 108
    .line 109
    move-result v2

    .line 110
    move v6, v4

    .line 111
    :goto_3
    if-ge v6, v2, :cond_7

    .line 112
    .line 113
    invoke-interface {p1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v7

    .line 117
    check-cast v7, Lp3/t;

    .line 118
    .line 119
    invoke-static {v7}, Lp3/s;->a(Lp3/t;)Z

    .line 120
    .line 121
    .line 122
    move-result v8

    .line 123
    if-nez v8, :cond_9

    .line 124
    .line 125
    iget-object v8, p0, Lp3/i0;->i:Lp3/j0;

    .line 126
    .line 127
    iget-wide v8, v8, Lp3/j0;->B:J

    .line 128
    .line 129
    invoke-virtual {p0}, Lp3/i0;->d()J

    .line 130
    .line 131
    .line 132
    move-result-wide v10

    .line 133
    invoke-static {v7, v8, v9, v10, v11}, Lp3/s;->f(Lp3/t;JJ)Z

    .line 134
    .line 135
    .line 136
    move-result v7

    .line 137
    if-eqz v7, :cond_6

    .line 138
    .line 139
    goto :goto_7

    .line 140
    :cond_6
    add-int/lit8 v6, v6, 0x1

    .line 141
    .line 142
    goto :goto_3

    .line 143
    :cond_7
    sget-object p1, Lp3/l;->f:Lp3/l;

    .line 144
    .line 145
    iput-object p0, v0, Lxf0/u2;->d:Lp3/i0;

    .line 146
    .line 147
    iput v3, v0, Lxf0/u2;->f:I

    .line 148
    .line 149
    invoke-virtual {p0, p1, v0}, Lp3/i0;->b(Lp3/l;Lkotlin/coroutines/Continuation;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object p1

    .line 153
    if-ne p1, v1, :cond_8

    .line 154
    .line 155
    :goto_4
    return-object v1

    .line 156
    :cond_8
    :goto_5
    check-cast p1, Lp3/k;

    .line 157
    .line 158
    iget-object p1, p1, Lp3/k;->a:Ljava/lang/Object;

    .line 159
    .line 160
    move-object v2, p1

    .line 161
    check-cast v2, Ljava/util/Collection;

    .line 162
    .line 163
    invoke-interface {v2}, Ljava/util/Collection;->size()I

    .line 164
    .line 165
    .line 166
    move-result v2

    .line 167
    move v6, v4

    .line 168
    :goto_6
    if-ge v6, v2, :cond_4

    .line 169
    .line 170
    invoke-interface {p1, v6}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 171
    .line 172
    .line 173
    move-result-object v7

    .line 174
    check-cast v7, Lp3/t;

    .line 175
    .line 176
    invoke-virtual {v7}, Lp3/t;->b()Z

    .line 177
    .line 178
    .line 179
    move-result v7

    .line 180
    if-eqz v7, :cond_a

    .line 181
    .line 182
    :cond_9
    :goto_7
    const/4 p0, 0x0

    .line 183
    return-object p0

    .line 184
    :cond_a
    add-int/lit8 v6, v6, 0x1

    .line 185
    .line 186
    goto :goto_6

    .line 187
    :cond_b
    add-int/lit8 v6, v6, 0x1

    .line 188
    .line 189
    goto :goto_2

    .line 190
    :cond_c
    invoke-interface {p1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 191
    .line 192
    .line 193
    move-result-object p0

    .line 194
    return-object p0
.end method
