.class public abstract Lhy0/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public static final a(Ll2/o;I)V
    .locals 25

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    check-cast v1, Ll2/t;

    .line 4
    .line 5
    const v2, 0x721debf2

    .line 6
    .line 7
    .line 8
    invoke-virtual {v1, v2}, Ll2/t;->a0(I)Ll2/t;

    .line 9
    .line 10
    .line 11
    const/4 v2, 0x1

    .line 12
    if-eqz p1, :cond_0

    .line 13
    .line 14
    move v3, v2

    .line 15
    goto :goto_0

    .line 16
    :cond_0
    const/4 v3, 0x0

    .line 17
    :goto_0
    and-int/lit8 v4, p1, 0x1

    .line 18
    .line 19
    invoke-virtual {v1, v4, v3}, Ll2/t;->O(IZ)Z

    .line 20
    .line 21
    .line 22
    move-result v3

    .line 23
    if-eqz v3, :cond_4

    .line 24
    .line 25
    sget-object v3, Landroidx/compose/foundation/layout/d;->c:Landroidx/compose/foundation/layout/FillElement;

    .line 26
    .line 27
    sget-object v4, Lk1/j;->e:Lk1/f;

    .line 28
    .line 29
    sget-object v5, Lx2/c;->q:Lx2/h;

    .line 30
    .line 31
    const/16 v6, 0x36

    .line 32
    .line 33
    invoke-static {v4, v5, v1, v6}, Lk1/r;->a(Lk1/i;Lx2/d;Ll2/o;I)Lk1/s;

    .line 34
    .line 35
    .line 36
    move-result-object v4

    .line 37
    iget-wide v5, v1, Ll2/t;->T:J

    .line 38
    .line 39
    invoke-static {v5, v6}, Ljava/lang/Long;->hashCode(J)I

    .line 40
    .line 41
    .line 42
    move-result v5

    .line 43
    invoke-virtual {v1}, Ll2/t;->m()Ll2/p1;

    .line 44
    .line 45
    .line 46
    move-result-object v6

    .line 47
    invoke-static {v1, v3}, Lx2/a;->c(Ll2/o;Lx2/s;)Lx2/s;

    .line 48
    .line 49
    .line 50
    move-result-object v3

    .line 51
    sget-object v7, Lv3/k;->m1:Lv3/j;

    .line 52
    .line 53
    invoke-virtual {v7}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 54
    .line 55
    .line 56
    sget-object v7, Lv3/j;->b:Lv3/i;

    .line 57
    .line 58
    invoke-virtual {v1}, Ll2/t;->c0()V

    .line 59
    .line 60
    .line 61
    iget-boolean v8, v1, Ll2/t;->S:Z

    .line 62
    .line 63
    if-eqz v8, :cond_1

    .line 64
    .line 65
    invoke-virtual {v1, v7}, Ll2/t;->l(Lay0/a;)V

    .line 66
    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_1
    invoke-virtual {v1}, Ll2/t;->m0()V

    .line 70
    .line 71
    .line 72
    :goto_1
    sget-object v7, Lv3/j;->g:Lv3/h;

    .line 73
    .line 74
    invoke-static {v7, v4, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 75
    .line 76
    .line 77
    sget-object v4, Lv3/j;->f:Lv3/h;

    .line 78
    .line 79
    invoke-static {v4, v6, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 80
    .line 81
    .line 82
    sget-object v4, Lv3/j;->j:Lv3/h;

    .line 83
    .line 84
    iget-boolean v6, v1, Ll2/t;->S:Z

    .line 85
    .line 86
    if-nez v6, :cond_2

    .line 87
    .line 88
    invoke-virtual {v1}, Ll2/t;->L()Ljava/lang/Object;

    .line 89
    .line 90
    .line 91
    move-result-object v6

    .line 92
    invoke-static {v5}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 93
    .line 94
    .line 95
    move-result-object v7

    .line 96
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 97
    .line 98
    .line 99
    move-result v6

    .line 100
    if-nez v6, :cond_3

    .line 101
    .line 102
    :cond_2
    invoke-static {v5, v1, v5, v4}, La7/g0;->s(ILl2/t;ILv3/h;)V

    .line 103
    .line 104
    .line 105
    :cond_3
    sget-object v4, Lv3/j;->d:Lv3/h;

    .line 106
    .line 107
    invoke-static {v4, v3, v1}, Ll2/b;->t(Lay0/n;Ljava/lang/Object;Ll2/o;)V

    .line 108
    .line 109
    .line 110
    const/16 v22, 0x0

    .line 111
    .line 112
    const v23, 0x3fffe

    .line 113
    .line 114
    .line 115
    move-object/from16 v20, v1

    .line 116
    .line 117
    const-string v1, "NOT YET IMPLEMENTED"

    .line 118
    .line 119
    move v3, v2

    .line 120
    const/4 v2, 0x0

    .line 121
    move v5, v3

    .line 122
    const-wide/16 v3, 0x0

    .line 123
    .line 124
    move v7, v5

    .line 125
    const-wide/16 v5, 0x0

    .line 126
    .line 127
    move v8, v7

    .line 128
    const/4 v7, 0x0

    .line 129
    move v10, v8

    .line 130
    const-wide/16 v8, 0x0

    .line 131
    .line 132
    move v11, v10

    .line 133
    const/4 v10, 0x0

    .line 134
    move v12, v11

    .line 135
    const/4 v11, 0x0

    .line 136
    move v14, v12

    .line 137
    const-wide/16 v12, 0x0

    .line 138
    .line 139
    move v15, v14

    .line 140
    const/4 v14, 0x0

    .line 141
    move/from16 v16, v15

    .line 142
    .line 143
    const/4 v15, 0x0

    .line 144
    move/from16 v17, v16

    .line 145
    .line 146
    const/16 v16, 0x0

    .line 147
    .line 148
    move/from16 v18, v17

    .line 149
    .line 150
    const/16 v17, 0x0

    .line 151
    .line 152
    move/from16 v19, v18

    .line 153
    .line 154
    const/16 v18, 0x0

    .line 155
    .line 156
    move/from16 v21, v19

    .line 157
    .line 158
    const/16 v19, 0x0

    .line 159
    .line 160
    move/from16 v24, v21

    .line 161
    .line 162
    const/16 v21, 0x6

    .line 163
    .line 164
    move/from16 v0, v24

    .line 165
    .line 166
    invoke-static/range {v1 .. v23}, Lh2/rb;->b(Ljava/lang/String;Lx2/s;JJLk4/x;JLr4/l;Lr4/k;JIZIILay0/k;Lg4/p0;Ll2/o;III)V

    .line 167
    .line 168
    .line 169
    move-object/from16 v1, v20

    .line 170
    .line 171
    invoke-virtual {v1, v0}, Ll2/t;->q(Z)V

    .line 172
    .line 173
    .line 174
    goto :goto_2

    .line 175
    :cond_4
    invoke-virtual {v1}, Ll2/t;->R()V

    .line 176
    .line 177
    .line 178
    :goto_2
    invoke-virtual {v1}, Ll2/t;->s()Ll2/u1;

    .line 179
    .line 180
    .line 181
    move-result-object v0

    .line 182
    if-eqz v0, :cond_5

    .line 183
    .line 184
    new-instance v1, Lym0/b;

    .line 185
    .line 186
    const/16 v2, 0x19

    .line 187
    .line 188
    move/from16 v3, p1

    .line 189
    .line 190
    invoke-direct {v1, v3, v2}, Lym0/b;-><init>(II)V

    .line 191
    .line 192
    .line 193
    iput-object v1, v0, Ll2/u1;->d:Lay0/n;

    .line 194
    .line 195
    :cond_5
    return-void
.end method

.method public static final b(Lx2/s;Ll2/o;I)V
    .locals 10

    .line 1
    move-object v7, p1

    .line 2
    check-cast v7, Ll2/t;

    .line 3
    .line 4
    const p1, -0x2c245f

    .line 5
    .line 6
    .line 7
    invoke-virtual {v7, p1}, Ll2/t;->a0(I)Ll2/t;

    .line 8
    .line 9
    .line 10
    invoke-virtual {v7, p0}, Ll2/t;->g(Ljava/lang/Object;)Z

    .line 11
    .line 12
    .line 13
    move-result p1

    .line 14
    const/4 v0, 0x2

    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    const/4 p1, 0x4

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move p1, v0

    .line 20
    :goto_0
    or-int/2addr p1, p2

    .line 21
    and-int/lit8 v1, p1, 0x3

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    if-eq v1, v0, :cond_1

    .line 25
    .line 26
    const/4 v0, 0x1

    .line 27
    goto :goto_1

    .line 28
    :cond_1
    move v0, v2

    .line 29
    :goto_1
    and-int/lit8 v1, p1, 0x1

    .line 30
    .line 31
    invoke-virtual {v7, v1, v0}, Ll2/t;->O(IZ)Z

    .line 32
    .line 33
    .line 34
    move-result v0

    .line 35
    if-eqz v0, :cond_2

    .line 36
    .line 37
    const v0, 0x7f0805e2

    .line 38
    .line 39
    .line 40
    invoke-static {v0, v2, v7}, Ljp/fa;->b(IILl2/o;)Li3/c;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    shl-int/lit8 p1, p1, 0x6

    .line 45
    .line 46
    and-int/lit16 p1, p1, 0x380

    .line 47
    .line 48
    or-int/lit16 v8, p1, 0x6030

    .line 49
    .line 50
    const/16 v9, 0x68

    .line 51
    .line 52
    const-string v1, "Background vehicle image"

    .line 53
    .line 54
    const/4 v3, 0x0

    .line 55
    sget-object v4, Lt3/j;->b:Lt3/x0;

    .line 56
    .line 57
    const/4 v5, 0x0

    .line 58
    const/4 v6, 0x0

    .line 59
    move-object v2, p0

    .line 60
    invoke-static/range {v0 .. v9}, Lkp/m;->a(Li3/c;Ljava/lang/String;Lx2/s;Lx2/e;Lt3/k;FLe3/m;Ll2/o;II)V

    .line 61
    .line 62
    .line 63
    goto :goto_2

    .line 64
    :cond_2
    move-object v2, p0

    .line 65
    invoke-virtual {v7}, Ll2/t;->R()V

    .line 66
    .line 67
    .line 68
    :goto_2
    invoke-virtual {v7}, Ll2/t;->s()Ll2/u1;

    .line 69
    .line 70
    .line 71
    move-result-object p0

    .line 72
    if-eqz p0, :cond_3

    .line 73
    .line 74
    new-instance p1, Ll30/a;

    .line 75
    .line 76
    const/4 v0, 0x3

    .line 77
    invoke-direct {p1, v2, p2, v0}, Ll30/a;-><init>(Lx2/s;II)V

    .line 78
    .line 79
    .line 80
    iput-object p1, p0, Ll2/u1;->d:Lay0/n;

    .line 81
    .line 82
    :cond_3
    return-void
.end method

.method public static final c(Ljava/lang/reflect/Type;)Ljava/lang/String;
    .locals 2

    .line 1
    instance-of v0, p0, Ljava/lang/Class;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    move-object v0, p0

    .line 6
    check-cast v0, Ljava/lang/Class;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Class;->isArray()Z

    .line 9
    .line 10
    .line 11
    move-result v1

    .line 12
    if-eqz v1, :cond_0

    .line 13
    .line 14
    sget-object v0, Lhy0/k0;->d:Lhy0/k0;

    .line 15
    .line 16
    invoke-static {p0, v0}, Lky0/l;->k(Ljava/lang/Object;Lay0/k;)Lky0/j;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    new-instance v0, Ljava/lang/StringBuilder;

    .line 21
    .line 22
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 23
    .line 24
    .line 25
    invoke-static {p0}, Lky0/l;->m(Lky0/j;)Ljava/lang/Object;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    check-cast v1, Ljava/lang/Class;

    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v1

    .line 35
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 36
    .line 37
    .line 38
    const-string v1, "[]"

    .line 39
    .line 40
    invoke-static {p0}, Lky0/l;->c(Lky0/j;)I

    .line 41
    .line 42
    .line 43
    move-result p0

    .line 44
    invoke-static {p0, v1}, Lly0/w;->s(ILjava/lang/String;)Ljava/lang/String;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 49
    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    return-object p0

    .line 56
    :cond_0
    invoke-virtual {v0}, Ljava/lang/Class;->getName()Ljava/lang/String;

    .line 57
    .line 58
    .line 59
    move-result-object p0

    .line 60
    return-object p0

    .line 61
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 62
    .line 63
    .line 64
    move-result-object p0

    .line 65
    return-object p0
.end method

.method public static final d(Lhy0/a0;Z)Ljava/lang/reflect/Type;
    .locals 3

    .line 1
    invoke-interface {p0}, Lhy0/a0;->getClassifier()Lhy0/e;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    instance-of v1, v0, Lhy0/b0;

    .line 6
    .line 7
    if-eqz v1, :cond_0

    .line 8
    .line 9
    new-instance p0, Lhy0/i0;

    .line 10
    .line 11
    check-cast v0, Lhy0/b0;

    .line 12
    .line 13
    invoke-direct {p0, v0}, Lhy0/i0;-><init>(Lhy0/b0;)V

    .line 14
    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_0
    instance-of v1, v0, Lhy0/d;

    .line 18
    .line 19
    if-eqz v1, :cond_b

    .line 20
    .line 21
    check-cast v0, Lhy0/d;

    .line 22
    .line 23
    if-eqz p1, :cond_1

    .line 24
    .line 25
    invoke-static {v0}, Ljp/p1;->d(Lhy0/d;)Ljava/lang/Class;

    .line 26
    .line 27
    .line 28
    move-result-object p1

    .line 29
    goto :goto_0

    .line 30
    :cond_1
    invoke-static {v0}, Ljp/p1;->c(Lhy0/d;)Ljava/lang/Class;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    :goto_0
    invoke-interface {p0}, Lhy0/a0;->getArguments()Ljava/util/List;

    .line 35
    .line 36
    .line 37
    move-result-object v0

    .line 38
    invoke-interface {v0}, Ljava/util/List;->isEmpty()Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    if-eqz v1, :cond_2

    .line 43
    .line 44
    goto :goto_3

    .line 45
    :cond_2
    invoke-virtual {p1}, Ljava/lang/Class;->isArray()Z

    .line 46
    .line 47
    .line 48
    move-result v1

    .line 49
    if-eqz v1, :cond_a

    .line 50
    .line 51
    invoke-virtual {p1}, Ljava/lang/Class;->getComponentType()Ljava/lang/Class;

    .line 52
    .line 53
    .line 54
    move-result-object v1

    .line 55
    invoke-virtual {v1}, Ljava/lang/Class;->isPrimitive()Z

    .line 56
    .line 57
    .line 58
    move-result v1

    .line 59
    if-eqz v1, :cond_3

    .line 60
    .line 61
    goto :goto_3

    .line 62
    :cond_3
    invoke-static {v0}, Lmx0/q;->k0(Ljava/util/List;)Ljava/lang/Object;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    check-cast v0, Lhy0/d0;

    .line 67
    .line 68
    if-eqz v0, :cond_9

    .line 69
    .line 70
    iget-object p0, v0, Lhy0/d0;->a:Lhy0/e0;

    .line 71
    .line 72
    iget-object v0, v0, Lhy0/d0;->b:Lhy0/a0;

    .line 73
    .line 74
    const/4 v1, -0x1

    .line 75
    if-nez p0, :cond_4

    .line 76
    .line 77
    move p0, v1

    .line 78
    goto :goto_1

    .line 79
    :cond_4
    sget-object v2, Lhy0/j0;->a:[I

    .line 80
    .line 81
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 82
    .line 83
    .line 84
    move-result p0

    .line 85
    aget p0, v2, p0

    .line 86
    .line 87
    :goto_1
    if-eq p0, v1, :cond_8

    .line 88
    .line 89
    const/4 v1, 0x1

    .line 90
    if-eq p0, v1, :cond_8

    .line 91
    .line 92
    const/4 v1, 0x2

    .line 93
    if-eq p0, v1, :cond_6

    .line 94
    .line 95
    const/4 v1, 0x3

    .line 96
    if-ne p0, v1, :cond_5

    .line 97
    .line 98
    goto :goto_2

    .line 99
    :cond_5
    new-instance p0, La8/r0;

    .line 100
    .line 101
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 102
    .line 103
    .line 104
    throw p0

    .line 105
    :cond_6
    :goto_2
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 106
    .line 107
    .line 108
    const/4 p0, 0x0

    .line 109
    invoke-static {v0, p0}, Lhy0/l0;->d(Lhy0/a0;Z)Ljava/lang/reflect/Type;

    .line 110
    .line 111
    .line 112
    move-result-object p0

    .line 113
    instance-of v0, p0, Ljava/lang/Class;

    .line 114
    .line 115
    if-eqz v0, :cond_7

    .line 116
    .line 117
    goto :goto_3

    .line 118
    :cond_7
    new-instance p1, Lhy0/a;

    .line 119
    .line 120
    invoke-direct {p1, p0}, Lhy0/a;-><init>(Ljava/lang/reflect/Type;)V

    .line 121
    .line 122
    .line 123
    :cond_8
    :goto_3
    return-object p1

    .line 124
    :cond_9
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 125
    .line 126
    new-instance v0, Ljava/lang/StringBuilder;

    .line 127
    .line 128
    const-string v1, "kotlin.Array must have exactly one type argument: "

    .line 129
    .line 130
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 134
    .line 135
    .line 136
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 137
    .line 138
    .line 139
    move-result-object p0

    .line 140
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 141
    .line 142
    .line 143
    throw p1

    .line 144
    :cond_a
    invoke-static {p1, v0}, Lhy0/l0;->e(Ljava/lang/Class;Ljava/util/List;)Lhy0/h0;

    .line 145
    .line 146
    .line 147
    move-result-object p0

    .line 148
    return-object p0

    .line 149
    :cond_b
    new-instance p1, Ljava/lang/UnsupportedOperationException;

    .line 150
    .line 151
    new-instance v0, Ljava/lang/StringBuilder;

    .line 152
    .line 153
    const-string v1, "Unsupported type classifier: "

    .line 154
    .line 155
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 156
    .line 157
    .line 158
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 159
    .line 160
    .line 161
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 162
    .line 163
    .line 164
    move-result-object p0

    .line 165
    invoke-direct {p1, p0}, Ljava/lang/UnsupportedOperationException;-><init>(Ljava/lang/String;)V

    .line 166
    .line 167
    .line 168
    throw p1
.end method

.method public static final e(Ljava/lang/Class;Ljava/util/List;)Lhy0/h0;
    .locals 4

    .line 1
    invoke-virtual {p0}, Ljava/lang/Class;->getDeclaringClass()Ljava/lang/Class;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    const/16 v1, 0xa

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    check-cast p1, Ljava/lang/Iterable;

    .line 10
    .line 11
    new-instance v0, Ljava/util/ArrayList;

    .line 12
    .line 13
    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    invoke-direct {v0, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 18
    .line 19
    .line 20
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 21
    .line 22
    .line 23
    move-result-object p1

    .line 24
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-eqz v1, :cond_0

    .line 29
    .line 30
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    check-cast v1, Lhy0/d0;

    .line 35
    .line 36
    invoke-static {v1}, Lhy0/l0;->f(Lhy0/d0;)Ljava/lang/reflect/Type;

    .line 37
    .line 38
    .line 39
    move-result-object v1

    .line 40
    invoke-virtual {v0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 41
    .line 42
    .line 43
    goto :goto_0

    .line 44
    :cond_0
    new-instance p1, Lhy0/h0;

    .line 45
    .line 46
    const/4 v1, 0x0

    .line 47
    invoke-direct {p1, p0, v1, v0}, Lhy0/h0;-><init>(Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/ArrayList;)V

    .line 48
    .line 49
    .line 50
    return-object p1

    .line 51
    :cond_1
    invoke-virtual {p0}, Ljava/lang/Class;->getModifiers()I

    .line 52
    .line 53
    .line 54
    move-result v2

    .line 55
    invoke-static {v2}, Ljava/lang/reflect/Modifier;->isStatic(I)Z

    .line 56
    .line 57
    .line 58
    move-result v2

    .line 59
    if-eqz v2, :cond_3

    .line 60
    .line 61
    check-cast p1, Ljava/lang/Iterable;

    .line 62
    .line 63
    new-instance v2, Ljava/util/ArrayList;

    .line 64
    .line 65
    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 66
    .line 67
    .line 68
    move-result v1

    .line 69
    invoke-direct {v2, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 70
    .line 71
    .line 72
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 73
    .line 74
    .line 75
    move-result-object p1

    .line 76
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 77
    .line 78
    .line 79
    move-result v1

    .line 80
    if-eqz v1, :cond_2

    .line 81
    .line 82
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 83
    .line 84
    .line 85
    move-result-object v1

    .line 86
    check-cast v1, Lhy0/d0;

    .line 87
    .line 88
    invoke-static {v1}, Lhy0/l0;->f(Lhy0/d0;)Ljava/lang/reflect/Type;

    .line 89
    .line 90
    .line 91
    move-result-object v1

    .line 92
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 93
    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_2
    new-instance p1, Lhy0/h0;

    .line 97
    .line 98
    invoke-direct {p1, p0, v0, v2}, Lhy0/h0;-><init>(Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/ArrayList;)V

    .line 99
    .line 100
    .line 101
    return-object p1

    .line 102
    :cond_3
    invoke-virtual {p0}, Ljava/lang/Class;->getTypeParameters()[Ljava/lang/reflect/TypeVariable;

    .line 103
    .line 104
    .line 105
    move-result-object v2

    .line 106
    array-length v2, v2

    .line 107
    invoke-interface {p1}, Ljava/util/List;->size()I

    .line 108
    .line 109
    .line 110
    move-result v3

    .line 111
    invoke-interface {p1, v2, v3}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 112
    .line 113
    .line 114
    move-result-object v3

    .line 115
    invoke-static {v0, v3}, Lhy0/l0;->e(Ljava/lang/Class;Ljava/util/List;)Lhy0/h0;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    const/4 v3, 0x0

    .line 120
    invoke-interface {p1, v3, v2}, Ljava/util/List;->subList(II)Ljava/util/List;

    .line 121
    .line 122
    .line 123
    move-result-object p1

    .line 124
    check-cast p1, Ljava/lang/Iterable;

    .line 125
    .line 126
    new-instance v2, Ljava/util/ArrayList;

    .line 127
    .line 128
    invoke-static {p1, v1}, Lmx0/o;->s(Ljava/lang/Iterable;I)I

    .line 129
    .line 130
    .line 131
    move-result v1

    .line 132
    invoke-direct {v2, v1}, Ljava/util/ArrayList;-><init>(I)V

    .line 133
    .line 134
    .line 135
    invoke-interface {p1}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 136
    .line 137
    .line 138
    move-result-object p1

    .line 139
    :goto_2
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 140
    .line 141
    .line 142
    move-result v1

    .line 143
    if-eqz v1, :cond_4

    .line 144
    .line 145
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 146
    .line 147
    .line 148
    move-result-object v1

    .line 149
    check-cast v1, Lhy0/d0;

    .line 150
    .line 151
    invoke-static {v1}, Lhy0/l0;->f(Lhy0/d0;)Ljava/lang/reflect/Type;

    .line 152
    .line 153
    .line 154
    move-result-object v1

    .line 155
    invoke-virtual {v2, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 156
    .line 157
    .line 158
    goto :goto_2

    .line 159
    :cond_4
    new-instance p1, Lhy0/h0;

    .line 160
    .line 161
    invoke-direct {p1, p0, v0, v2}, Lhy0/h0;-><init>(Ljava/lang/Class;Ljava/lang/reflect/Type;Ljava/util/ArrayList;)V

    .line 162
    .line 163
    .line 164
    return-object p1
.end method

.method public static final f(Lhy0/d0;)Ljava/lang/reflect/Type;
    .locals 4

    .line 1
    iget-object v0, p0, Lhy0/d0;->a:Lhy0/e0;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object p0, Lhy0/m0;->f:Lhy0/m0;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    iget-object p0, p0, Lhy0/d0;->b:Lhy0/a0;

    .line 9
    .line 10
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 14
    .line 15
    .line 16
    move-result v0

    .line 17
    const/4 v1, 0x1

    .line 18
    if-eqz v0, :cond_3

    .line 19
    .line 20
    const/4 v2, 0x0

    .line 21
    if-eq v0, v1, :cond_2

    .line 22
    .line 23
    const/4 v3, 0x2

    .line 24
    if-ne v0, v3, :cond_1

    .line 25
    .line 26
    new-instance v0, Lhy0/m0;

    .line 27
    .line 28
    invoke-static {p0, v1}, Lhy0/l0;->d(Lhy0/a0;Z)Ljava/lang/reflect/Type;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    invoke-direct {v0, p0, v2}, Lhy0/m0;-><init>(Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;)V

    .line 33
    .line 34
    .line 35
    return-object v0

    .line 36
    :cond_1
    new-instance p0, La8/r0;

    .line 37
    .line 38
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_2
    new-instance v0, Lhy0/m0;

    .line 43
    .line 44
    invoke-static {p0, v1}, Lhy0/l0;->d(Lhy0/a0;Z)Ljava/lang/reflect/Type;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    invoke-direct {v0, v2, p0}, Lhy0/m0;-><init>(Ljava/lang/reflect/Type;Ljava/lang/reflect/Type;)V

    .line 49
    .line 50
    .line 51
    return-object v0

    .line 52
    :cond_3
    invoke-static {p0, v1}, Lhy0/l0;->d(Lhy0/a0;Z)Ljava/lang/reflect/Type;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method

.method public static final g(Lt2/b;Lrx0/c;)V
    .locals 4

    .line 1
    instance-of v0, p1, La7/n0;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-object v0, p1

    .line 6
    check-cast v0, La7/n0;

    .line 7
    .line 8
    iget v1, v0, La7/n0;->e:I

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
    iput v1, v0, La7/n0;->e:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, La7/n0;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p1, v0, La7/n0;->d:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v1, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v1, v0, La7/n0;->e:I

    .line 30
    .line 31
    const/4 v2, 0x1

    .line 32
    if-eqz v1, :cond_2

    .line 33
    .line 34
    if-eq v1, v2, :cond_1

    .line 35
    .line 36
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "call to \'resume\' before \'invoke\' with coroutine"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    invoke-static {p1}, Lc1/j0;->i(Ljava/lang/Object;)La8/r0;

    .line 45
    .line 46
    .line 47
    move-result-object p0

    .line 48
    throw p0

    .line 49
    :cond_2
    invoke-static {p1}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    invoke-interface {v0}, Lkotlin/coroutines/Continuation;->getContext()Lpx0/g;

    .line 53
    .line 54
    .line 55
    move-result-object p1

    .line 56
    sget-object v1, La7/a0;->d:La7/a0;

    .line 57
    .line 58
    invoke-interface {p1, v1}, Lpx0/g;->get(Lpx0/f;)Lpx0/e;

    .line 59
    .line 60
    .line 61
    move-result-object p1

    .line 62
    check-cast p1, La7/q;

    .line 63
    .line 64
    if-eqz p1, :cond_3

    .line 65
    .line 66
    iput v2, v0, La7/n0;->e:I

    .line 67
    .line 68
    invoke-virtual {p1, p0, v0}, La7/q;->c(Lay0/n;Lrx0/c;)V

    .line 69
    .line 70
    .line 71
    return-void

    .line 72
    :cond_3
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 73
    .line 74
    const-string p1, "provideContent requires a ContentReceiver and should only be called from GlanceAppWidget.provideGlance"

    .line 75
    .line 76
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 77
    .line 78
    .line 79
    throw p0
.end method

.method public static final h(La7/m0;Landroid/content/Context;Lrx0/c;)Ljava/lang/Object;
    .locals 7

    .line 1
    instance-of v0, p2, La7/o0;

    .line 2
    .line 3
    const/high16 v1, -0x80000000

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    move-object v0, p2

    .line 8
    check-cast v0, La7/o0;

    .line 9
    .line 10
    iget v2, v0, La7/o0;->h:I

    .line 11
    .line 12
    and-int v3, v2, v1

    .line 13
    .line 14
    if-eqz v3, :cond_0

    .line 15
    .line 16
    sub-int/2addr v2, v1

    .line 17
    iput v2, v0, La7/o0;->h:I

    .line 18
    .line 19
    goto :goto_0

    .line 20
    :cond_0
    new-instance v0, La7/o0;

    .line 21
    .line 22
    invoke-direct {v0, p2}, Lrx0/c;-><init>(Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    :goto_0
    iget-object p2, v0, La7/o0;->g:Ljava/lang/Object;

    .line 26
    .line 27
    sget-object v2, Lqx0/a;->d:Lqx0/a;

    .line 28
    .line 29
    iget v3, v0, La7/o0;->h:I

    .line 30
    .line 31
    const/4 v4, 0x2

    .line 32
    const/4 v5, 0x1

    .line 33
    if-eqz v3, :cond_3

    .line 34
    .line 35
    if-eq v3, v5, :cond_2

    .line 36
    .line 37
    if-ne v3, v4, :cond_1

    .line 38
    .line 39
    iget-object p0, v0, La7/o0;->f:Ljava/util/Iterator;

    .line 40
    .line 41
    iget-object p1, v0, La7/o0;->e:Landroid/content/Context;

    .line 42
    .line 43
    iget-object v3, v0, La7/o0;->d:La7/m0;

    .line 44
    .line 45
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 46
    .line 47
    .line 48
    goto :goto_2

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
    iget-object p1, v0, La7/o0;->e:Landroid/content/Context;

    .line 58
    .line 59
    iget-object p0, v0, La7/o0;->d:La7/m0;

    .line 60
    .line 61
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 62
    .line 63
    .line 64
    goto :goto_1

    .line 65
    :cond_3
    invoke-static {p2}, Lps/t1;->k(Ljava/lang/Object;)V

    .line 66
    .line 67
    .line 68
    new-instance p2, La7/v0;

    .line 69
    .line 70
    invoke-direct {p2, p1}, La7/v0;-><init>(Landroid/content/Context;)V

    .line 71
    .line 72
    .line 73
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 74
    .line 75
    .line 76
    move-result-object v3

    .line 77
    iput-object p0, v0, La7/o0;->d:La7/m0;

    .line 78
    .line 79
    iput-object p1, v0, La7/o0;->e:Landroid/content/Context;

    .line 80
    .line 81
    iput v5, v0, La7/o0;->h:I

    .line 82
    .line 83
    invoke-virtual {p2, v3, v0}, La7/v0;->a(Ljava/lang/Class;Lrx0/c;)Ljava/io/Serializable;

    .line 84
    .line 85
    .line 86
    move-result-object p2

    .line 87
    if-ne p2, v2, :cond_4

    .line 88
    .line 89
    goto :goto_3

    .line 90
    :cond_4
    :goto_1
    check-cast p2, Ljava/lang/Iterable;

    .line 91
    .line 92
    invoke-interface {p2}, Ljava/lang/Iterable;->iterator()Ljava/util/Iterator;

    .line 93
    .line 94
    .line 95
    move-result-object p2

    .line 96
    move-object v3, p0

    .line 97
    move-object p0, p2

    .line 98
    :cond_5
    :goto_2
    invoke-interface {p0}, Ljava/util/Iterator;->hasNext()Z

    .line 99
    .line 100
    .line 101
    move-result p2

    .line 102
    sget-object v5, Llx0/b0;->a:Llx0/b0;

    .line 103
    .line 104
    if-eqz p2, :cond_9

    .line 105
    .line 106
    invoke-interface {p0}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 107
    .line 108
    .line 109
    move-result-object p2

    .line 110
    check-cast p2, La7/c;

    .line 111
    .line 112
    iput-object v3, v0, La7/o0;->d:La7/m0;

    .line 113
    .line 114
    iput-object p1, v0, La7/o0;->e:Landroid/content/Context;

    .line 115
    .line 116
    iput-object p0, v0, La7/o0;->f:Ljava/util/Iterator;

    .line 117
    .line 118
    iput v4, v0, La7/o0;->h:I

    .line 119
    .line 120
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 121
    .line 122
    .line 123
    instance-of v6, p2, La7/c;

    .line 124
    .line 125
    if-eqz v6, :cond_8

    .line 126
    .line 127
    iget p2, p2, La7/c;->a:I

    .line 128
    .line 129
    if-gt v1, p2, :cond_6

    .line 130
    .line 131
    const/4 v6, -0x1

    .line 132
    if-lt p2, v6, :cond_8

    .line 133
    .line 134
    :cond_6
    invoke-static {v3, p1, p2, v0}, La7/m0;->c(La7/m0;Landroid/content/Context;ILrx0/c;)Ljava/lang/Object;

    .line 135
    .line 136
    .line 137
    move-result-object p2

    .line 138
    sget-object v6, Lqx0/a;->d:Lqx0/a;

    .line 139
    .line 140
    if-ne p2, v6, :cond_7

    .line 141
    .line 142
    move-object v5, p2

    .line 143
    :cond_7
    if-ne v5, v2, :cond_5

    .line 144
    .line 145
    :goto_3
    return-object v2

    .line 146
    :cond_8
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 147
    .line 148
    const-string p1, "Invalid Glance ID"

    .line 149
    .line 150
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 151
    .line 152
    .line 153
    throw p0

    .line 154
    :cond_9
    return-object v5
.end method
