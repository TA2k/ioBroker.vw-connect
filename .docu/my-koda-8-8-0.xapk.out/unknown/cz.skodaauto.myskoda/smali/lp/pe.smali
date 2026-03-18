.class public abstract Llp/pe;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Lxj0/f;Lxj0/f;)I
    .locals 12

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "location"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-wide v0, p0, Lxj0/f;->a:D

    .line 12
    .line 13
    const-wide v2, 0x400921fb54442d18L    # Math.PI

    .line 14
    .line 15
    .line 16
    .line 17
    .line 18
    mul-double v4, v0, v2

    .line 19
    .line 20
    const/16 v6, 0xb4

    .line 21
    .line 22
    int-to-double v6, v6

    .line 23
    div-double/2addr v4, v6

    .line 24
    iget-wide v8, p1, Lxj0/f;->a:D

    .line 25
    .line 26
    mul-double v10, v8, v2

    .line 27
    .line 28
    div-double/2addr v10, v6

    .line 29
    sub-double/2addr v8, v0

    .line 30
    mul-double/2addr v8, v2

    .line 31
    div-double/2addr v8, v6

    .line 32
    iget-wide v0, p1, Lxj0/f;->b:D

    .line 33
    .line 34
    iget-wide p0, p0, Lxj0/f;->b:D

    .line 35
    .line 36
    sub-double/2addr v0, p0

    .line 37
    mul-double/2addr v0, v2

    .line 38
    div-double/2addr v0, v6

    .line 39
    const/4 p0, 0x2

    .line 40
    int-to-double p0, p0

    .line 41
    div-double/2addr v8, p0

    .line 42
    invoke-static {v8, v9}, Ljava/lang/Math;->sin(D)D

    .line 43
    .line 44
    .line 45
    move-result-wide v2

    .line 46
    invoke-static {v8, v9}, Ljava/lang/Math;->sin(D)D

    .line 47
    .line 48
    .line 49
    move-result-wide v6

    .line 50
    mul-double/2addr v6, v2

    .line 51
    invoke-static {v4, v5}, Ljava/lang/Math;->cos(D)D

    .line 52
    .line 53
    .line 54
    move-result-wide v2

    .line 55
    invoke-static {v10, v11}, Ljava/lang/Math;->cos(D)D

    .line 56
    .line 57
    .line 58
    move-result-wide v4

    .line 59
    mul-double/2addr v4, v2

    .line 60
    div-double/2addr v0, p0

    .line 61
    invoke-static {v0, v1}, Ljava/lang/Math;->sin(D)D

    .line 62
    .line 63
    .line 64
    move-result-wide v2

    .line 65
    mul-double/2addr v2, v4

    .line 66
    invoke-static {v0, v1}, Ljava/lang/Math;->sin(D)D

    .line 67
    .line 68
    .line 69
    move-result-wide v0

    .line 70
    mul-double/2addr v0, v2

    .line 71
    add-double/2addr v0, v6

    .line 72
    invoke-static {v0, v1}, Ljava/lang/Math;->sqrt(D)D

    .line 73
    .line 74
    .line 75
    move-result-wide v2

    .line 76
    const/4 v4, 0x1

    .line 77
    int-to-double v4, v4

    .line 78
    sub-double/2addr v4, v0

    .line 79
    invoke-static {v4, v5}, Ljava/lang/Math;->sqrt(D)D

    .line 80
    .line 81
    .line 82
    move-result-wide v0

    .line 83
    invoke-static {v2, v3, v0, v1}, Ljava/lang/Math;->atan2(DD)D

    .line 84
    .line 85
    .line 86
    move-result-wide v0

    .line 87
    mul-double/2addr v0, p0

    .line 88
    const-wide p0, 0x41584dae00000000L    # 6371000.0

    .line 89
    .line 90
    .line 91
    .line 92
    .line 93
    mul-double/2addr v0, p0

    .line 94
    invoke-static {v0, v1}, Lcy0/a;->h(D)I

    .line 95
    .line 96
    .line 97
    move-result p0

    .line 98
    return p0
.end method

.method public static final b(JJ)J
    .locals 7

    .line 1
    invoke-static {p0, p1}, Lg4/o0;->f(J)I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p0, p1}, Lg4/o0;->e(J)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-static {p2, p3}, Lg4/o0;->f(J)I

    .line 10
    .line 11
    .line 12
    move-result v2

    .line 13
    invoke-static {p0, p1}, Lg4/o0;->e(J)I

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    const/4 v4, 0x0

    .line 18
    const/4 v5, 0x1

    .line 19
    if-ge v2, v3, :cond_0

    .line 20
    .line 21
    move v2, v5

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    move v2, v4

    .line 24
    :goto_0
    invoke-static {p0, p1}, Lg4/o0;->f(J)I

    .line 25
    .line 26
    .line 27
    move-result v3

    .line 28
    invoke-static {p2, p3}, Lg4/o0;->e(J)I

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    if-ge v3, v6, :cond_1

    .line 33
    .line 34
    move v3, v5

    .line 35
    goto :goto_1

    .line 36
    :cond_1
    move v3, v4

    .line 37
    :goto_1
    and-int/2addr v2, v3

    .line 38
    if-eqz v2, :cond_9

    .line 39
    .line 40
    invoke-static {p2, p3}, Lg4/o0;->f(J)I

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    invoke-static {p0, p1}, Lg4/o0;->f(J)I

    .line 45
    .line 46
    .line 47
    move-result v3

    .line 48
    if-gt v2, v3, :cond_2

    .line 49
    .line 50
    move v2, v5

    .line 51
    goto :goto_2

    .line 52
    :cond_2
    move v2, v4

    .line 53
    :goto_2
    invoke-static {p0, p1}, Lg4/o0;->e(J)I

    .line 54
    .line 55
    .line 56
    move-result v3

    .line 57
    invoke-static {p2, p3}, Lg4/o0;->e(J)I

    .line 58
    .line 59
    .line 60
    move-result v6

    .line 61
    if-gt v3, v6, :cond_3

    .line 62
    .line 63
    move v3, v5

    .line 64
    goto :goto_3

    .line 65
    :cond_3
    move v3, v4

    .line 66
    :goto_3
    and-int/2addr v2, v3

    .line 67
    if-eqz v2, :cond_4

    .line 68
    .line 69
    invoke-static {p2, p3}, Lg4/o0;->f(J)I

    .line 70
    .line 71
    .line 72
    move-result v0

    .line 73
    move v1, v0

    .line 74
    goto :goto_6

    .line 75
    :cond_4
    invoke-static {p0, p1}, Lg4/o0;->f(J)I

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    invoke-static {p2, p3}, Lg4/o0;->f(J)I

    .line 80
    .line 81
    .line 82
    move-result v3

    .line 83
    if-gt v2, v3, :cond_5

    .line 84
    .line 85
    move v2, v5

    .line 86
    goto :goto_4

    .line 87
    :cond_5
    move v2, v4

    .line 88
    :goto_4
    invoke-static {p2, p3}, Lg4/o0;->e(J)I

    .line 89
    .line 90
    .line 91
    move-result v3

    .line 92
    invoke-static {p0, p1}, Lg4/o0;->e(J)I

    .line 93
    .line 94
    .line 95
    move-result p0

    .line 96
    if-gt v3, p0, :cond_6

    .line 97
    .line 98
    move v4, v5

    .line 99
    :cond_6
    and-int p0, v2, v4

    .line 100
    .line 101
    if-eqz p0, :cond_7

    .line 102
    .line 103
    invoke-static {p2, p3}, Lg4/o0;->d(J)I

    .line 104
    .line 105
    .line 106
    move-result p0

    .line 107
    :goto_5
    sub-int/2addr v1, p0

    .line 108
    goto :goto_6

    .line 109
    :cond_7
    invoke-static {p2, p3}, Lg4/o0;->f(J)I

    .line 110
    .line 111
    .line 112
    move-result p0

    .line 113
    invoke-static {p2, p3}, Lg4/o0;->e(J)I

    .line 114
    .line 115
    .line 116
    move-result p1

    .line 117
    if-ge v0, p1, :cond_8

    .line 118
    .line 119
    if-gt p0, v0, :cond_8

    .line 120
    .line 121
    invoke-static {p2, p3}, Lg4/o0;->f(J)I

    .line 122
    .line 123
    .line 124
    move-result v0

    .line 125
    invoke-static {p2, p3}, Lg4/o0;->d(J)I

    .line 126
    .line 127
    .line 128
    move-result p0

    .line 129
    goto :goto_5

    .line 130
    :cond_8
    invoke-static {p2, p3}, Lg4/o0;->f(J)I

    .line 131
    .line 132
    .line 133
    move-result v1

    .line 134
    goto :goto_6

    .line 135
    :cond_9
    invoke-static {p2, p3}, Lg4/o0;->f(J)I

    .line 136
    .line 137
    .line 138
    move-result p0

    .line 139
    if-le v1, p0, :cond_a

    .line 140
    .line 141
    invoke-static {p2, p3}, Lg4/o0;->d(J)I

    .line 142
    .line 143
    .line 144
    move-result p0

    .line 145
    sub-int/2addr v0, p0

    .line 146
    invoke-static {p2, p3}, Lg4/o0;->d(J)I

    .line 147
    .line 148
    .line 149
    move-result p0

    .line 150
    goto :goto_5

    .line 151
    :cond_a
    :goto_6
    invoke-static {v0, v1}, Lg4/f0;->b(II)J

    .line 152
    .line 153
    .line 154
    move-result-wide p0

    .line 155
    return-wide p0
.end method

.method public static final c(Ljava/util/Collection;)Lxj0/v;
    .locals 11

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p0, Ljava/lang/Iterable;

    .line 7
    .line 8
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 13
    .line 14
    .line 15
    move-result v1

    .line 16
    if-eqz v1, :cond_7

    .line 17
    .line 18
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    check-cast v1, Lxj0/f;

    .line 23
    .line 24
    iget-wide v1, v1, Lxj0/f;->a:D

    .line 25
    .line 26
    :goto_0
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 27
    .line 28
    .line 29
    move-result v3

    .line 30
    if-eqz v3, :cond_0

    .line 31
    .line 32
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    move-result-object v3

    .line 36
    check-cast v3, Lxj0/f;

    .line 37
    .line 38
    iget-wide v3, v3, Lxj0/f;->a:D

    .line 39
    .line 40
    invoke-static {v1, v2, v3, v4}, Ljava/lang/Math;->max(DD)D

    .line 41
    .line 42
    .line 43
    move-result-wide v1

    .line 44
    goto :goto_0

    .line 45
    :cond_0
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 46
    .line 47
    .line 48
    move-result-object v0

    .line 49
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 50
    .line 51
    .line 52
    move-result v3

    .line 53
    if-eqz v3, :cond_6

    .line 54
    .line 55
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    check-cast v3, Lxj0/f;

    .line 60
    .line 61
    iget-wide v3, v3, Lxj0/f;->a:D

    .line 62
    .line 63
    :goto_1
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 64
    .line 65
    .line 66
    move-result v5

    .line 67
    if-eqz v5, :cond_1

    .line 68
    .line 69
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    check-cast v5, Lxj0/f;

    .line 74
    .line 75
    iget-wide v5, v5, Lxj0/f;->a:D

    .line 76
    .line 77
    invoke-static {v3, v4, v5, v6}, Ljava/lang/Math;->min(DD)D

    .line 78
    .line 79
    .line 80
    move-result-wide v3

    .line 81
    goto :goto_1

    .line 82
    :cond_1
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 83
    .line 84
    .line 85
    move-result-object v0

    .line 86
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 87
    .line 88
    .line 89
    move-result v5

    .line 90
    if-eqz v5, :cond_5

    .line 91
    .line 92
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 93
    .line 94
    .line 95
    move-result-object v5

    .line 96
    check-cast v5, Lxj0/f;

    .line 97
    .line 98
    iget-wide v5, v5, Lxj0/f;->b:D

    .line 99
    .line 100
    :goto_2
    invoke-interface {v0}, Ljava/util/Iterator;->hasNext()Z

    .line 101
    .line 102
    .line 103
    move-result v7

    .line 104
    if-eqz v7, :cond_2

    .line 105
    .line 106
    invoke-interface {v0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object v7

    .line 110
    check-cast v7, Lxj0/f;

    .line 111
    .line 112
    iget-wide v7, v7, Lxj0/f;->b:D

    .line 113
    .line 114
    invoke-static {v5, v6, v7, v8}, Ljava/lang/Math;->max(DD)D

    .line 115
    .line 116
    .line 117
    move-result-wide v5

    .line 118
    goto :goto_2

    .line 119
    :cond_2
    invoke-interface {p0}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 120
    .line 121
    .line 122
    move-result-object p0

    .line 123
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 124
    .line 125
    .line 126
    move-result v0

    .line 127
    if-eqz v0, :cond_4

    .line 128
    .line 129
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 130
    .line 131
    .line 132
    move-result-object v0

    .line 133
    check-cast v0, Lxj0/f;

    .line 134
    .line 135
    iget-wide v7, v0, Lxj0/f;->b:D

    .line 136
    .line 137
    :goto_3
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 138
    .line 139
    .line 140
    move-result v0

    .line 141
    if-eqz v0, :cond_3

    .line 142
    .line 143
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v0

    .line 147
    check-cast v0, Lxj0/f;

    .line 148
    .line 149
    iget-wide v9, v0, Lxj0/f;->b:D

    .line 150
    .line 151
    invoke-static {v7, v8, v9, v10}, Ljava/lang/Math;->min(DD)D

    .line 152
    .line 153
    .line 154
    move-result-wide v7

    .line 155
    goto :goto_3

    .line 156
    :cond_3
    new-instance p0, Lxj0/f;

    .line 157
    .line 158
    invoke-direct {p0, v3, v4, v7, v8}, Lxj0/f;-><init>(DD)V

    .line 159
    .line 160
    .line 161
    new-instance v0, Lxj0/f;

    .line 162
    .line 163
    invoke-direct {v0, v1, v2, v5, v6}, Lxj0/f;-><init>(DD)V

    .line 164
    .line 165
    .line 166
    new-instance v1, Lxj0/v;

    .line 167
    .line 168
    invoke-direct {v1, p0, v0}, Lxj0/v;-><init>(Lxj0/f;Lxj0/f;)V

    .line 169
    .line 170
    .line 171
    return-object v1

    .line 172
    :cond_4
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 173
    .line 174
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 175
    .line 176
    .line 177
    throw p0

    .line 178
    :cond_5
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 179
    .line 180
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 181
    .line 182
    .line 183
    throw p0

    .line 184
    :cond_6
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 185
    .line 186
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 187
    .line 188
    .line 189
    throw p0

    .line 190
    :cond_7
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 191
    .line 192
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 193
    .line 194
    .line 195
    throw p0
.end method
