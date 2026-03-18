.class public abstract Llp/sc;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/i2;Ljava/lang/Integer;ILjava/lang/Integer;)Ljava/util/List;
    .locals 4

    .line 1
    iget-boolean v0, p0, Ll2/i2;->w:Z

    .line 2
    .line 3
    if-nez v0, :cond_6

    .line 4
    .line 5
    invoke-virtual {p0}, Ll2/i2;->p()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_6

    .line 10
    .line 11
    new-instance v0, Lw2/h;

    .line 12
    .line 13
    invoke-direct {v0, p0}, Lw2/h;-><init>(Ljava/lang/Object;)V

    .line 14
    .line 15
    .line 16
    if-eqz p3, :cond_0

    .line 17
    .line 18
    invoke-virtual {p3}, Ljava/lang/Integer;->intValue()I

    .line 19
    .line 20
    .line 21
    move-result p3

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    iget p3, p0, Ll2/i2;->v:I

    .line 24
    .line 25
    if-gez p3, :cond_1

    .line 26
    .line 27
    iget-object p3, p0, Ll2/i2;->b:[I

    .line 28
    .line 29
    invoke-virtual {p0, p2, p3}, Ll2/i2;->D(I[I)I

    .line 30
    .line 31
    .line 32
    move-result p3

    .line 33
    :cond_1
    :goto_0
    if-nez p1, :cond_3

    .line 34
    .line 35
    iget p1, p0, Ll2/i2;->i:I

    .line 36
    .line 37
    iget-object v1, p0, Ll2/i2;->b:[I

    .line 38
    .line 39
    invoke-virtual {p0, p2}, Ll2/i2;->r(I)I

    .line 40
    .line 41
    .line 42
    move-result v2

    .line 43
    invoke-virtual {p0, v2, v1}, Ll2/i2;->M(I[I)I

    .line 44
    .line 45
    .line 46
    move-result v1

    .line 47
    sub-int/2addr p1, v1

    .line 48
    iget-object v1, p0, Ll2/i2;->s:Landroidx/collection/b0;

    .line 49
    .line 50
    if-eqz v1, :cond_2

    .line 51
    .line 52
    invoke-virtual {v1, p2}, Landroidx/collection/p;->b(I)Ljava/lang/Object;

    .line 53
    .line 54
    .line 55
    move-result-object v1

    .line 56
    check-cast v1, Landroidx/collection/l0;

    .line 57
    .line 58
    if-eqz v1, :cond_2

    .line 59
    .line 60
    iget v1, v1, Landroidx/collection/l0;->b:I

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_2
    const/4 v1, 0x0

    .line 64
    :goto_1
    add-int/2addr p1, v1

    .line 65
    invoke-static {p1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 66
    .line 67
    .line 68
    move-result-object p1

    .line 69
    :cond_3
    :goto_2
    if-ltz p2, :cond_5

    .line 70
    .line 71
    invoke-virtual {p0, p2}, Ll2/i2;->N(I)Ll2/p0;

    .line 72
    .line 73
    .line 74
    move-result-object v1

    .line 75
    invoke-virtual {v0, v1, p1}, Lap0/o;->O(Ll2/p0;Ljava/lang/Object;)V

    .line 76
    .line 77
    .line 78
    invoke-virtual {p0, p2}, Ll2/i2;->b(I)Ll2/a;

    .line 79
    .line 80
    .line 81
    move-result-object p1

    .line 82
    if-ltz p3, :cond_4

    .line 83
    .line 84
    iget-object p2, p0, Ll2/i2;->b:[I

    .line 85
    .line 86
    invoke-virtual {p0, p3, p2}, Ll2/i2;->D(I[I)I

    .line 87
    .line 88
    .line 89
    move-result p2

    .line 90
    move v3, p3

    .line 91
    move p3, p2

    .line 92
    move p2, v3

    .line 93
    goto :goto_2

    .line 94
    :cond_4
    move p2, p3

    .line 95
    goto :goto_2

    .line 96
    :cond_5
    iget-object p0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 97
    .line 98
    check-cast p0, Ljava/util/ArrayList;

    .line 99
    .line 100
    return-object p0

    .line 101
    :cond_6
    sget-object p0, Lmx0/s;->d:Lmx0/s;

    .line 102
    .line 103
    return-object p0
.end method

.method public static final b(Ll2/e2;Ll2/x;II)Ljava/lang/Integer;
    .locals 5

    .line 1
    iget-object v0, p0, Ll2/e2;->b:[I

    .line 2
    .line 3
    :goto_0
    const/4 v1, 0x0

    .line 4
    if-ge p2, p3, :cond_3

    .line 5
    .line 6
    mul-int/lit8 v2, p2, 0x5

    .line 7
    .line 8
    add-int/lit8 v2, v2, 0x3

    .line 9
    .line 10
    aget v2, v0, v2

    .line 11
    .line 12
    add-int/2addr v2, p2

    .line 13
    invoke-virtual {p0, p2}, Ll2/e2;->j(I)Z

    .line 14
    .line 15
    .line 16
    move-result v3

    .line 17
    if-eqz v3, :cond_1

    .line 18
    .line 19
    invoke-virtual {p0, p2}, Ll2/e2;->i(I)I

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    const/16 v4, 0xce

    .line 24
    .line 25
    if-ne v3, v4, :cond_1

    .line 26
    .line 27
    invoke-virtual {p0, p2, v0}, Ll2/e2;->p(I[I)Ljava/lang/Object;

    .line 28
    .line 29
    .line 30
    move-result-object v3

    .line 31
    sget-object v4, Ll2/v;->e:Ll2/d1;

    .line 32
    .line 33
    invoke-static {v3, v4}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result v3

    .line 37
    if-eqz v3, :cond_1

    .line 38
    .line 39
    const/4 v3, 0x0

    .line 40
    invoke-virtual {p0, p2, v3}, Ll2/e2;->h(II)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    instance-of v4, v3, Ll2/q;

    .line 45
    .line 46
    if-eqz v4, :cond_0

    .line 47
    .line 48
    move-object v1, v3

    .line 49
    check-cast v1, Ll2/q;

    .line 50
    .line 51
    :cond_0
    if-eqz v1, :cond_1

    .line 52
    .line 53
    iget-object v1, v1, Ll2/q;->d:Ll2/r;

    .line 54
    .line 55
    invoke-virtual {v1, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-eqz v1, :cond_1

    .line 60
    .line 61
    invoke-static {p2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0

    .line 66
    :cond_1
    invoke-virtual {p0, p2}, Ll2/e2;->d(I)Z

    .line 67
    .line 68
    .line 69
    move-result v1

    .line 70
    if-eqz v1, :cond_2

    .line 71
    .line 72
    add-int/lit8 p2, p2, 0x1

    .line 73
    .line 74
    invoke-static {p0, p1, p2, v2}, Llp/sc;->b(Ll2/e2;Ll2/x;II)Ljava/lang/Integer;

    .line 75
    .line 76
    .line 77
    move-result-object p2

    .line 78
    if-eqz p2, :cond_2

    .line 79
    .line 80
    invoke-virtual {p2}, Ljava/lang/Number;->intValue()I

    .line 81
    .line 82
    .line 83
    move-result p0

    .line 84
    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 85
    .line 86
    .line 87
    move-result-object p0

    .line 88
    return-object p0

    .line 89
    :cond_2
    move p2, v2

    .line 90
    goto :goto_0

    .line 91
    :cond_3
    return-object v1
.end method

.method public static final c(Lkotlin/reflect/jvm/internal/KPropertyImpl;)Z
    .locals 2

    .line 1
    instance-of v0, p0, Lhy0/o;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_3

    .line 5
    .line 6
    invoke-static {p0}, Ljy0/a;->a(Lhy0/z;)Ljava/lang/reflect/Field;

    .line 7
    .line 8
    .line 9
    move-result-object v0

    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    invoke-virtual {v0}, Ljava/lang/reflect/AccessibleObject;->isAccessible()Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v0, v1

    .line 18
    :goto_0
    if-eqz v0, :cond_6

    .line 19
    .line 20
    invoke-interface {p0}, Lhy0/z;->getGetter()Lhy0/s;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    invoke-static {v0}, Ljy0/a;->b(Lhy0/g;)Ljava/lang/reflect/Method;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    if-eqz v0, :cond_1

    .line 29
    .line 30
    invoke-virtual {v0}, Ljava/lang/reflect/AccessibleObject;->isAccessible()Z

    .line 31
    .line 32
    .line 33
    move-result v0

    .line 34
    goto :goto_1

    .line 35
    :cond_1
    move v0, v1

    .line 36
    :goto_1
    if-eqz v0, :cond_6

    .line 37
    .line 38
    check-cast p0, Lhy0/o;

    .line 39
    .line 40
    invoke-interface {p0}, Lhy0/o;->getSetter()Lhy0/h;

    .line 41
    .line 42
    .line 43
    move-result-object p0

    .line 44
    invoke-static {p0}, Ljy0/a;->b(Lhy0/g;)Ljava/lang/reflect/Method;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    if-eqz p0, :cond_2

    .line 49
    .line 50
    invoke-virtual {p0}, Ljava/lang/reflect/AccessibleObject;->isAccessible()Z

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    goto :goto_2

    .line 55
    :cond_2
    move p0, v1

    .line 56
    :goto_2
    if-eqz p0, :cond_6

    .line 57
    .line 58
    goto :goto_5

    .line 59
    :cond_3
    invoke-static {p0}, Ljy0/a;->a(Lhy0/z;)Ljava/lang/reflect/Field;

    .line 60
    .line 61
    .line 62
    move-result-object v0

    .line 63
    if-eqz v0, :cond_4

    .line 64
    .line 65
    invoke-virtual {v0}, Ljava/lang/reflect/AccessibleObject;->isAccessible()Z

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    goto :goto_3

    .line 70
    :cond_4
    move v0, v1

    .line 71
    :goto_3
    if-eqz v0, :cond_6

    .line 72
    .line 73
    invoke-interface {p0}, Lhy0/z;->getGetter()Lhy0/s;

    .line 74
    .line 75
    .line 76
    move-result-object p0

    .line 77
    invoke-static {p0}, Ljy0/a;->b(Lhy0/g;)Ljava/lang/reflect/Method;

    .line 78
    .line 79
    .line 80
    move-result-object p0

    .line 81
    if-eqz p0, :cond_5

    .line 82
    .line 83
    invoke-virtual {p0}, Ljava/lang/reflect/AccessibleObject;->isAccessible()Z

    .line 84
    .line 85
    .line 86
    move-result p0

    .line 87
    goto :goto_4

    .line 88
    :cond_5
    move p0, v1

    .line 89
    :goto_4
    if-eqz p0, :cond_6

    .line 90
    .line 91
    :goto_5
    return v1

    .line 92
    :cond_6
    const/4 p0, 0x0

    .line 93
    return p0
.end method

.method public static final d(Lhy0/c;)V
    .locals 4

    .line 1
    instance-of v0, p0, Lhy0/o;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    if-eqz v0, :cond_2

    .line 5
    .line 6
    move-object v0, p0

    .line 7
    check-cast v0, Lhy0/z;

    .line 8
    .line 9
    invoke-static {v0}, Ljy0/a;->a(Lhy0/z;)Ljava/lang/reflect/Field;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    if-eqz v2, :cond_0

    .line 14
    .line 15
    invoke-virtual {v2, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 16
    .line 17
    .line 18
    :cond_0
    invoke-interface {v0}, Lhy0/z;->getGetter()Lhy0/s;

    .line 19
    .line 20
    .line 21
    move-result-object v0

    .line 22
    invoke-static {v0}, Ljy0/a;->b(Lhy0/g;)Ljava/lang/reflect/Method;

    .line 23
    .line 24
    .line 25
    move-result-object v0

    .line 26
    if-eqz v0, :cond_1

    .line 27
    .line 28
    invoke-virtual {v0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 29
    .line 30
    .line 31
    :cond_1
    check-cast p0, Lhy0/o;

    .line 32
    .line 33
    invoke-interface {p0}, Lhy0/o;->getSetter()Lhy0/h;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    invoke-static {p0}, Ljy0/a;->b(Lhy0/g;)Ljava/lang/reflect/Method;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    if-eqz p0, :cond_f

    .line 42
    .line 43
    invoke-virtual {p0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 44
    .line 45
    .line 46
    return-void

    .line 47
    :cond_2
    instance-of v0, p0, Lhy0/z;

    .line 48
    .line 49
    if-eqz v0, :cond_4

    .line 50
    .line 51
    check-cast p0, Lhy0/z;

    .line 52
    .line 53
    invoke-static {p0}, Ljy0/a;->a(Lhy0/z;)Ljava/lang/reflect/Field;

    .line 54
    .line 55
    .line 56
    move-result-object v0

    .line 57
    if-eqz v0, :cond_3

    .line 58
    .line 59
    invoke-virtual {v0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 60
    .line 61
    .line 62
    :cond_3
    invoke-interface {p0}, Lhy0/z;->getGetter()Lhy0/s;

    .line 63
    .line 64
    .line 65
    move-result-object p0

    .line 66
    invoke-static {p0}, Ljy0/a;->b(Lhy0/g;)Ljava/lang/reflect/Method;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    if-eqz p0, :cond_f

    .line 71
    .line 72
    invoke-virtual {p0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 73
    .line 74
    .line 75
    return-void

    .line 76
    :cond_4
    instance-of v0, p0, Lhy0/s;

    .line 77
    .line 78
    if-eqz v0, :cond_6

    .line 79
    .line 80
    move-object v0, p0

    .line 81
    check-cast v0, Lhy0/s;

    .line 82
    .line 83
    invoke-interface {v0}, Lhy0/r;->getProperty()Lhy0/z;

    .line 84
    .line 85
    .line 86
    move-result-object v0

    .line 87
    invoke-static {v0}, Ljy0/a;->a(Lhy0/z;)Ljava/lang/reflect/Field;

    .line 88
    .line 89
    .line 90
    move-result-object v0

    .line 91
    if-eqz v0, :cond_5

    .line 92
    .line 93
    invoke-virtual {v0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 94
    .line 95
    .line 96
    :cond_5
    check-cast p0, Lhy0/g;

    .line 97
    .line 98
    invoke-static {p0}, Ljy0/a;->b(Lhy0/g;)Ljava/lang/reflect/Method;

    .line 99
    .line 100
    .line 101
    move-result-object p0

    .line 102
    if-eqz p0, :cond_f

    .line 103
    .line 104
    invoke-virtual {p0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 105
    .line 106
    .line 107
    return-void

    .line 108
    :cond_6
    instance-of v0, p0, Lhy0/h;

    .line 109
    .line 110
    if-eqz v0, :cond_8

    .line 111
    .line 112
    move-object v0, p0

    .line 113
    check-cast v0, Lhy0/h;

    .line 114
    .line 115
    invoke-interface {v0}, Lhy0/r;->getProperty()Lhy0/z;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    invoke-static {v0}, Ljy0/a;->a(Lhy0/z;)Ljava/lang/reflect/Field;

    .line 120
    .line 121
    .line 122
    move-result-object v0

    .line 123
    if-eqz v0, :cond_7

    .line 124
    .line 125
    invoke-virtual {v0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 126
    .line 127
    .line 128
    :cond_7
    check-cast p0, Lhy0/g;

    .line 129
    .line 130
    invoke-static {p0}, Ljy0/a;->b(Lhy0/g;)Ljava/lang/reflect/Method;

    .line 131
    .line 132
    .line 133
    move-result-object p0

    .line 134
    if-eqz p0, :cond_f

    .line 135
    .line 136
    invoke-virtual {p0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 137
    .line 138
    .line 139
    return-void

    .line 140
    :cond_8
    instance-of v0, p0, Lhy0/g;

    .line 141
    .line 142
    if-eqz v0, :cond_10

    .line 143
    .line 144
    move-object v0, p0

    .line 145
    check-cast v0, Lhy0/g;

    .line 146
    .line 147
    invoke-static {v0}, Ljy0/a;->b(Lhy0/g;)Ljava/lang/reflect/Method;

    .line 148
    .line 149
    .line 150
    move-result-object v2

    .line 151
    if-eqz v2, :cond_9

    .line 152
    .line 153
    invoke-virtual {v2, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 154
    .line 155
    .line 156
    :cond_9
    invoke-static {p0}, Lkotlin/reflect/jvm/internal/UtilKt;->asKCallableImpl(Ljava/lang/Object;)Lkotlin/reflect/jvm/internal/KCallableImpl;

    .line 157
    .line 158
    .line 159
    move-result-object p0

    .line 160
    const/4 v2, 0x0

    .line 161
    if-eqz p0, :cond_a

    .line 162
    .line 163
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/KCallableImpl;->getDefaultCaller()Lkotlin/reflect/jvm/internal/calls/Caller;

    .line 164
    .line 165
    .line 166
    move-result-object p0

    .line 167
    if-eqz p0, :cond_a

    .line 168
    .line 169
    invoke-interface {p0}, Lkotlin/reflect/jvm/internal/calls/Caller;->getMember()Ljava/lang/reflect/Member;

    .line 170
    .line 171
    .line 172
    move-result-object p0

    .line 173
    goto :goto_0

    .line 174
    :cond_a
    move-object p0, v2

    .line 175
    :goto_0
    instance-of v3, p0, Ljava/lang/reflect/AccessibleObject;

    .line 176
    .line 177
    if-eqz v3, :cond_b

    .line 178
    .line 179
    check-cast p0, Ljava/lang/reflect/AccessibleObject;

    .line 180
    .line 181
    goto :goto_1

    .line 182
    :cond_b
    move-object p0, v2

    .line 183
    :goto_1
    if-eqz p0, :cond_c

    .line 184
    .line 185
    invoke-virtual {p0, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 186
    .line 187
    .line 188
    :cond_c
    invoke-static {v0}, Lkotlin/reflect/jvm/internal/UtilKt;->asKCallableImpl(Ljava/lang/Object;)Lkotlin/reflect/jvm/internal/KCallableImpl;

    .line 189
    .line 190
    .line 191
    move-result-object p0

    .line 192
    if-eqz p0, :cond_d

    .line 193
    .line 194
    invoke-virtual {p0}, Lkotlin/reflect/jvm/internal/KCallableImpl;->getCaller()Lkotlin/reflect/jvm/internal/calls/Caller;

    .line 195
    .line 196
    .line 197
    move-result-object p0

    .line 198
    if-eqz p0, :cond_d

    .line 199
    .line 200
    invoke-interface {p0}, Lkotlin/reflect/jvm/internal/calls/Caller;->getMember()Ljava/lang/reflect/Member;

    .line 201
    .line 202
    .line 203
    move-result-object p0

    .line 204
    goto :goto_2

    .line 205
    :cond_d
    move-object p0, v2

    .line 206
    :goto_2
    instance-of v0, p0, Ljava/lang/reflect/Constructor;

    .line 207
    .line 208
    if-eqz v0, :cond_e

    .line 209
    .line 210
    move-object v2, p0

    .line 211
    check-cast v2, Ljava/lang/reflect/Constructor;

    .line 212
    .line 213
    :cond_e
    if-eqz v2, :cond_f

    .line 214
    .line 215
    invoke-virtual {v2, v1}, Ljava/lang/reflect/AccessibleObject;->setAccessible(Z)V

    .line 216
    .line 217
    .line 218
    :cond_f
    return-void

    .line 219
    :cond_10
    new-instance v0, Ljava/lang/UnsupportedOperationException;

    .line 220
    .line 221
    new-instance v1, Ljava/lang/StringBuilder;

    .line 222
    .line 223
    const-string v2, "Unknown callable: "

    .line 224
    .line 225
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 226
    .line 227
    .line 228
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 229
    .line 230
    .line 231
    const-string v2, " ("

    .line 232
    .line 233
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 234
    .line 235
    .line 236
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 237
    .line 238
    .line 239
    move-result-object p0

    .line 240
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 241
    .line 242
    .line 243
    const/16 p0, 0x29

    .line 244
    .line 245
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 246
    .line 247
    .line 248
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 249
    .line 250
    .line 251
    move-result-object p0

    .line 252
    invoke-direct {v0, p0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 253
    .line 254
    .line 255
    throw v0
.end method

.method public static final e(Ll2/e2;ILjava/lang/Integer;)Ljava/util/ArrayList;
    .locals 5

    .line 1
    new-instance v0, Lw2/h;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lw2/h;-><init>(Ljava/lang/Object;)V

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1}, Ll2/e2;->q(I)I

    .line 7
    .line 8
    .line 9
    move-result v1

    .line 10
    invoke-virtual {p0, p1}, Ll2/e2;->a(I)Ll2/a;

    .line 11
    .line 12
    .line 13
    move-result-object v2

    .line 14
    :goto_0
    if-ltz p1, :cond_1

    .line 15
    .line 16
    iget-object v3, p0, Ll2/e2;->a:Ll2/f2;

    .line 17
    .line 18
    invoke-virtual {v3, p1}, Ll2/f2;->m(I)Ll2/p0;

    .line 19
    .line 20
    .line 21
    move-result-object p1

    .line 22
    invoke-virtual {v0, p1, p2}, Lap0/o;->O(Ll2/p0;Ljava/lang/Object;)V

    .line 23
    .line 24
    .line 25
    if-ltz v1, :cond_0

    .line 26
    .line 27
    invoke-virtual {p0, v1}, Ll2/e2;->a(I)Ll2/a;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    invoke-virtual {p0, v1}, Ll2/e2;->q(I)I

    .line 32
    .line 33
    .line 34
    move-result p2

    .line 35
    move-object v4, v2

    .line 36
    move-object v2, p1

    .line 37
    move p1, v1

    .line 38
    move v1, p2

    .line 39
    move-object p2, v4

    .line 40
    goto :goto_0

    .line 41
    :cond_0
    move p1, v1

    .line 42
    move-object p2, v2

    .line 43
    goto :goto_0

    .line 44
    :cond_1
    iget-object p0, v0, Lap0/o;->e:Ljava/lang/Object;

    .line 45
    .line 46
    check-cast p0, Ljava/util/ArrayList;

    .line 47
    .line 48
    return-object p0
.end method
