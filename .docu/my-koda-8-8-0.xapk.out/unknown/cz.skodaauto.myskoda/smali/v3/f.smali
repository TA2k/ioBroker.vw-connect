.class public abstract Lv3/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lv3/d;

.field public static final b:Lv3/l1;


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lv3/d;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lv3/d;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lv3/f;->a:Lv3/d;

    .line 8
    .line 9
    new-instance v0, Lv3/l1;

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    invoke-direct {v0, v1}, Lv3/l1;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lv3/f;->b:Lv3/l1;

    .line 16
    .line 17
    return-void
.end method

.method public static final A(Lv3/m;Ljava/lang/Object;Lay0/k;)V
    .locals 10

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Lx2/r;

    .line 3
    .line 4
    iget-object v1, v0, Lx2/r;->d:Lx2/r;

    .line 5
    .line 6
    iget-boolean v1, v1, Lx2/r;->q:Z

    .line 7
    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    const-string v1, "visitAncestors called on an unattached node"

    .line 11
    .line 12
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object v0, v0, Lx2/r;->d:Lx2/r;

    .line 16
    .line 17
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 18
    .line 19
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    :goto_0
    if-eqz p0, :cond_e

    .line 24
    .line 25
    iget-object v1, p0, Lv3/h0;->H:Lg1/q;

    .line 26
    .line 27
    iget-object v1, v1, Lg1/q;->g:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v1, Lx2/r;

    .line 30
    .line 31
    iget v1, v1, Lx2/r;->g:I

    .line 32
    .line 33
    const/high16 v2, 0x40000

    .line 34
    .line 35
    and-int/2addr v1, v2

    .line 36
    const/4 v3, 0x0

    .line 37
    if-eqz v1, :cond_c

    .line 38
    .line 39
    :goto_1
    if-eqz v0, :cond_c

    .line 40
    .line 41
    iget v1, v0, Lx2/r;->f:I

    .line 42
    .line 43
    and-int/2addr v1, v2

    .line 44
    if-eqz v1, :cond_b

    .line 45
    .line 46
    move-object v1, v0

    .line 47
    move-object v4, v3

    .line 48
    :goto_2
    if-eqz v1, :cond_b

    .line 49
    .line 50
    instance-of v5, v1, Lv3/c2;

    .line 51
    .line 52
    const/4 v6, 0x1

    .line 53
    if-eqz v5, :cond_2

    .line 54
    .line 55
    check-cast v1, Lv3/c2;

    .line 56
    .line 57
    invoke-interface {v1}, Lv3/c2;->g()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v5

    .line 61
    invoke-virtual {p1, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 62
    .line 63
    .line 64
    move-result v5

    .line 65
    if-eqz v5, :cond_1

    .line 66
    .line 67
    invoke-interface {p2, v1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 68
    .line 69
    .line 70
    move-result-object v1

    .line 71
    check-cast v1, Ljava/lang/Boolean;

    .line 72
    .line 73
    invoke-virtual {v1}, Ljava/lang/Boolean;->booleanValue()Z

    .line 74
    .line 75
    .line 76
    move-result v6

    .line 77
    :cond_1
    if-nez v6, :cond_a

    .line 78
    .line 79
    goto/16 :goto_7

    .line 80
    .line 81
    :cond_2
    iget v5, v1, Lx2/r;->f:I

    .line 82
    .line 83
    and-int/2addr v5, v2

    .line 84
    const/4 v7, 0x0

    .line 85
    if-eqz v5, :cond_3

    .line 86
    .line 87
    move v5, v6

    .line 88
    goto :goto_3

    .line 89
    :cond_3
    move v5, v7

    .line 90
    :goto_3
    if-eqz v5, :cond_a

    .line 91
    .line 92
    instance-of v5, v1, Lv3/n;

    .line 93
    .line 94
    if-eqz v5, :cond_a

    .line 95
    .line 96
    move-object v5, v1

    .line 97
    check-cast v5, Lv3/n;

    .line 98
    .line 99
    iget-object v5, v5, Lv3/n;->s:Lx2/r;

    .line 100
    .line 101
    move v8, v7

    .line 102
    :goto_4
    if-eqz v5, :cond_9

    .line 103
    .line 104
    iget v9, v5, Lx2/r;->f:I

    .line 105
    .line 106
    and-int/2addr v9, v2

    .line 107
    if-eqz v9, :cond_4

    .line 108
    .line 109
    move v9, v6

    .line 110
    goto :goto_5

    .line 111
    :cond_4
    move v9, v7

    .line 112
    :goto_5
    if-eqz v9, :cond_8

    .line 113
    .line 114
    add-int/lit8 v8, v8, 0x1

    .line 115
    .line 116
    if-ne v8, v6, :cond_5

    .line 117
    .line 118
    move-object v1, v5

    .line 119
    goto :goto_6

    .line 120
    :cond_5
    if-nez v4, :cond_6

    .line 121
    .line 122
    new-instance v4, Ln2/b;

    .line 123
    .line 124
    const/16 v9, 0x10

    .line 125
    .line 126
    new-array v9, v9, [Lx2/r;

    .line 127
    .line 128
    invoke-direct {v4, v9}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 129
    .line 130
    .line 131
    :cond_6
    if-eqz v1, :cond_7

    .line 132
    .line 133
    invoke-virtual {v4, v1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 134
    .line 135
    .line 136
    move-object v1, v3

    .line 137
    :cond_7
    invoke-virtual {v4, v5}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 138
    .line 139
    .line 140
    :cond_8
    :goto_6
    iget-object v5, v5, Lx2/r;->i:Lx2/r;

    .line 141
    .line 142
    goto :goto_4

    .line 143
    :cond_9
    if-ne v8, v6, :cond_a

    .line 144
    .line 145
    goto :goto_2

    .line 146
    :cond_a
    invoke-static {v4}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 147
    .line 148
    .line 149
    move-result-object v1

    .line 150
    goto :goto_2

    .line 151
    :cond_b
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 152
    .line 153
    goto :goto_1

    .line 154
    :cond_c
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 155
    .line 156
    .line 157
    move-result-object p0

    .line 158
    if-eqz p0, :cond_d

    .line 159
    .line 160
    iget-object v0, p0, Lv3/h0;->H:Lg1/q;

    .line 161
    .line 162
    if-eqz v0, :cond_d

    .line 163
    .line 164
    iget-object v0, v0, Lg1/q;->f:Ljava/lang/Object;

    .line 165
    .line 166
    check-cast v0, Lv3/z1;

    .line 167
    .line 168
    goto/16 :goto_0

    .line 169
    .line 170
    :cond_d
    move-object v0, v3

    .line 171
    goto/16 :goto_0

    .line 172
    .line 173
    :cond_e
    :goto_7
    return-void
.end method

.method public static final B(Lv3/c2;Lay0/k;)V
    .locals 11

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Lx2/r;

    .line 3
    .line 4
    iget-object v1, v0, Lx2/r;->d:Lx2/r;

    .line 5
    .line 6
    iget-boolean v1, v1, Lx2/r;->q:Z

    .line 7
    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    const-string v1, "visitAncestors called on an unattached node"

    .line 11
    .line 12
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object v0, v0, Lx2/r;->d:Lx2/r;

    .line 16
    .line 17
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 18
    .line 19
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    :goto_0
    if-eqz v1, :cond_e

    .line 24
    .line 25
    iget-object v2, v1, Lv3/h0;->H:Lg1/q;

    .line 26
    .line 27
    iget-object v2, v2, Lg1/q;->g:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v2, Lx2/r;

    .line 30
    .line 31
    iget v2, v2, Lx2/r;->g:I

    .line 32
    .line 33
    const/high16 v3, 0x40000

    .line 34
    .line 35
    and-int/2addr v2, v3

    .line 36
    const/4 v4, 0x0

    .line 37
    if-eqz v2, :cond_c

    .line 38
    .line 39
    :goto_1
    if-eqz v0, :cond_c

    .line 40
    .line 41
    iget v2, v0, Lx2/r;->f:I

    .line 42
    .line 43
    and-int/2addr v2, v3

    .line 44
    if-eqz v2, :cond_b

    .line 45
    .line 46
    move-object v2, v0

    .line 47
    move-object v5, v4

    .line 48
    :goto_2
    if-eqz v2, :cond_b

    .line 49
    .line 50
    instance-of v6, v2, Lv3/c2;

    .line 51
    .line 52
    const/4 v7, 0x1

    .line 53
    if-eqz v6, :cond_2

    .line 54
    .line 55
    check-cast v2, Lv3/c2;

    .line 56
    .line 57
    invoke-interface {p0}, Lv3/c2;->g()Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v6

    .line 61
    invoke-interface {v2}, Lv3/c2;->g()Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v8

    .line 65
    invoke-static {v6, v8}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 66
    .line 67
    .line 68
    move-result v6

    .line 69
    if-eqz v6, :cond_1

    .line 70
    .line 71
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 72
    .line 73
    .line 74
    move-result-object v6

    .line 75
    invoke-virtual {v2}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 76
    .line 77
    .line 78
    move-result-object v8

    .line 79
    if-ne v6, v8, :cond_1

    .line 80
    .line 81
    invoke-interface {p1, v2}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object v2

    .line 85
    check-cast v2, Ljava/lang/Boolean;

    .line 86
    .line 87
    invoke-virtual {v2}, Ljava/lang/Boolean;->booleanValue()Z

    .line 88
    .line 89
    .line 90
    move-result v7

    .line 91
    :cond_1
    if-nez v7, :cond_a

    .line 92
    .line 93
    goto/16 :goto_7

    .line 94
    .line 95
    :cond_2
    iget v6, v2, Lx2/r;->f:I

    .line 96
    .line 97
    and-int/2addr v6, v3

    .line 98
    const/4 v8, 0x0

    .line 99
    if-eqz v6, :cond_3

    .line 100
    .line 101
    move v6, v7

    .line 102
    goto :goto_3

    .line 103
    :cond_3
    move v6, v8

    .line 104
    :goto_3
    if-eqz v6, :cond_a

    .line 105
    .line 106
    instance-of v6, v2, Lv3/n;

    .line 107
    .line 108
    if-eqz v6, :cond_a

    .line 109
    .line 110
    move-object v6, v2

    .line 111
    check-cast v6, Lv3/n;

    .line 112
    .line 113
    iget-object v6, v6, Lv3/n;->s:Lx2/r;

    .line 114
    .line 115
    move v9, v8

    .line 116
    :goto_4
    if-eqz v6, :cond_9

    .line 117
    .line 118
    iget v10, v6, Lx2/r;->f:I

    .line 119
    .line 120
    and-int/2addr v10, v3

    .line 121
    if-eqz v10, :cond_4

    .line 122
    .line 123
    move v10, v7

    .line 124
    goto :goto_5

    .line 125
    :cond_4
    move v10, v8

    .line 126
    :goto_5
    if-eqz v10, :cond_8

    .line 127
    .line 128
    add-int/lit8 v9, v9, 0x1

    .line 129
    .line 130
    if-ne v9, v7, :cond_5

    .line 131
    .line 132
    move-object v2, v6

    .line 133
    goto :goto_6

    .line 134
    :cond_5
    if-nez v5, :cond_6

    .line 135
    .line 136
    new-instance v5, Ln2/b;

    .line 137
    .line 138
    const/16 v10, 0x10

    .line 139
    .line 140
    new-array v10, v10, [Lx2/r;

    .line 141
    .line 142
    invoke-direct {v5, v10}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 143
    .line 144
    .line 145
    :cond_6
    if-eqz v2, :cond_7

    .line 146
    .line 147
    invoke-virtual {v5, v2}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    move-object v2, v4

    .line 151
    :cond_7
    invoke-virtual {v5, v6}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 152
    .line 153
    .line 154
    :cond_8
    :goto_6
    iget-object v6, v6, Lx2/r;->i:Lx2/r;

    .line 155
    .line 156
    goto :goto_4

    .line 157
    :cond_9
    if-ne v9, v7, :cond_a

    .line 158
    .line 159
    goto :goto_2

    .line 160
    :cond_a
    invoke-static {v5}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 161
    .line 162
    .line 163
    move-result-object v2

    .line 164
    goto :goto_2

    .line 165
    :cond_b
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 166
    .line 167
    goto/16 :goto_1

    .line 168
    .line 169
    :cond_c
    invoke-virtual {v1}, Lv3/h0;->v()Lv3/h0;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    if-eqz v1, :cond_d

    .line 174
    .line 175
    iget-object v0, v1, Lv3/h0;->H:Lg1/q;

    .line 176
    .line 177
    if-eqz v0, :cond_d

    .line 178
    .line 179
    iget-object v0, v0, Lg1/q;->f:Ljava/lang/Object;

    .line 180
    .line 181
    check-cast v0, Lv3/z1;

    .line 182
    .line 183
    goto/16 :goto_0

    .line 184
    .line 185
    :cond_d
    move-object v0, v4

    .line 186
    goto/16 :goto_0

    .line 187
    .line 188
    :cond_e
    :goto_7
    return-void
.end method

.method public static final C(Lv3/c2;Lay0/k;)V
    .locals 12

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Lx2/r;

    .line 3
    .line 4
    iget-object v1, v0, Lx2/r;->d:Lx2/r;

    .line 5
    .line 6
    iget-boolean v1, v1, Lx2/r;->q:Z

    .line 7
    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    const-string v1, "visitSubtreeIf called on an unattached node"

    .line 11
    .line 12
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    new-instance v1, Ln2/b;

    .line 16
    .line 17
    const/16 v2, 0x10

    .line 18
    .line 19
    new-array v3, v2, [Lx2/r;

    .line 20
    .line 21
    invoke-direct {v1, v3}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 22
    .line 23
    .line 24
    iget-object v0, v0, Lx2/r;->d:Lx2/r;

    .line 25
    .line 26
    iget-object v3, v0, Lx2/r;->i:Lx2/r;

    .line 27
    .line 28
    if-nez v3, :cond_1

    .line 29
    .line 30
    invoke-static {v1, v0}, Lv3/f;->b(Ln2/b;Lx2/r;)V

    .line 31
    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_1
    invoke-virtual {v1, v3}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    :cond_2
    :goto_0
    iget v0, v1, Ln2/b;->f:I

    .line 38
    .line 39
    if-eqz v0, :cond_e

    .line 40
    .line 41
    add-int/lit8 v0, v0, -0x1

    .line 42
    .line 43
    invoke-virtual {v1, v0}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    check-cast v0, Lx2/r;

    .line 48
    .line 49
    iget v3, v0, Lx2/r;->g:I

    .line 50
    .line 51
    const/high16 v4, 0x40000

    .line 52
    .line 53
    and-int/2addr v3, v4

    .line 54
    if-eqz v3, :cond_d

    .line 55
    .line 56
    move-object v3, v0

    .line 57
    :goto_1
    if-eqz v3, :cond_d

    .line 58
    .line 59
    iget v5, v3, Lx2/r;->f:I

    .line 60
    .line 61
    and-int/2addr v5, v4

    .line 62
    if-eqz v5, :cond_c

    .line 63
    .line 64
    const/4 v5, 0x0

    .line 65
    move-object v6, v3

    .line 66
    move-object v7, v5

    .line 67
    :goto_2
    if-eqz v6, :cond_c

    .line 68
    .line 69
    instance-of v8, v6, Lv3/c2;

    .line 70
    .line 71
    if-eqz v8, :cond_5

    .line 72
    .line 73
    check-cast v6, Lv3/c2;

    .line 74
    .line 75
    invoke-interface {p0}, Lv3/c2;->g()Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    move-result-object v8

    .line 79
    invoke-interface {v6}, Lv3/c2;->g()Ljava/lang/Object;

    .line 80
    .line 81
    .line 82
    move-result-object v9

    .line 83
    invoke-static {v8, v9}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 84
    .line 85
    .line 86
    move-result v8

    .line 87
    if-eqz v8, :cond_3

    .line 88
    .line 89
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 90
    .line 91
    .line 92
    move-result-object v8

    .line 93
    invoke-virtual {v6}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 94
    .line 95
    .line 96
    move-result-object v9

    .line 97
    if-ne v8, v9, :cond_3

    .line 98
    .line 99
    invoke-interface {p1, v6}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object v6

    .line 103
    check-cast v6, Lv3/b2;

    .line 104
    .line 105
    goto :goto_3

    .line 106
    :cond_3
    sget-object v6, Lv3/b2;->d:Lv3/b2;

    .line 107
    .line 108
    :goto_3
    sget-object v8, Lv3/b2;->f:Lv3/b2;

    .line 109
    .line 110
    if-ne v6, v8, :cond_4

    .line 111
    .line 112
    goto :goto_7

    .line 113
    :cond_4
    sget-object v8, Lv3/b2;->e:Lv3/b2;

    .line 114
    .line 115
    if-eq v6, v8, :cond_2

    .line 116
    .line 117
    goto :goto_6

    .line 118
    :cond_5
    iget v8, v6, Lx2/r;->f:I

    .line 119
    .line 120
    and-int/2addr v8, v4

    .line 121
    if-eqz v8, :cond_b

    .line 122
    .line 123
    instance-of v8, v6, Lv3/n;

    .line 124
    .line 125
    if-eqz v8, :cond_b

    .line 126
    .line 127
    move-object v8, v6

    .line 128
    check-cast v8, Lv3/n;

    .line 129
    .line 130
    iget-object v8, v8, Lv3/n;->s:Lx2/r;

    .line 131
    .line 132
    const/4 v9, 0x0

    .line 133
    :goto_4
    const/4 v10, 0x1

    .line 134
    if-eqz v8, :cond_a

    .line 135
    .line 136
    iget v11, v8, Lx2/r;->f:I

    .line 137
    .line 138
    and-int/2addr v11, v4

    .line 139
    if-eqz v11, :cond_9

    .line 140
    .line 141
    add-int/lit8 v9, v9, 0x1

    .line 142
    .line 143
    if-ne v9, v10, :cond_6

    .line 144
    .line 145
    move-object v6, v8

    .line 146
    goto :goto_5

    .line 147
    :cond_6
    if-nez v7, :cond_7

    .line 148
    .line 149
    new-instance v7, Ln2/b;

    .line 150
    .line 151
    new-array v10, v2, [Lx2/r;

    .line 152
    .line 153
    invoke-direct {v7, v10}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 154
    .line 155
    .line 156
    :cond_7
    if-eqz v6, :cond_8

    .line 157
    .line 158
    invoke-virtual {v7, v6}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 159
    .line 160
    .line 161
    move-object v6, v5

    .line 162
    :cond_8
    invoke-virtual {v7, v8}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 163
    .line 164
    .line 165
    :cond_9
    :goto_5
    iget-object v8, v8, Lx2/r;->i:Lx2/r;

    .line 166
    .line 167
    goto :goto_4

    .line 168
    :cond_a
    if-ne v9, v10, :cond_b

    .line 169
    .line 170
    goto :goto_2

    .line 171
    :cond_b
    :goto_6
    invoke-static {v7}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 172
    .line 173
    .line 174
    move-result-object v6

    .line 175
    goto :goto_2

    .line 176
    :cond_c
    iget-object v3, v3, Lx2/r;->i:Lx2/r;

    .line 177
    .line 178
    goto :goto_1

    .line 179
    :cond_d
    invoke-static {v1, v0}, Lv3/f;->b(Ln2/b;Lx2/r;)V

    .line 180
    .line 181
    .line 182
    goto/16 :goto_0

    .line 183
    .line 184
    :cond_e
    :goto_7
    return-void
.end method

.method public static final a(FZZ)J
    .locals 4

    .line 1
    invoke-static {p0}, Ljava/lang/Float;->floatToRawIntBits(F)I

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    int-to-long v0, p0

    .line 6
    const-wide/16 v2, 0x0

    .line 7
    .line 8
    if-eqz p1, :cond_0

    .line 9
    .line 10
    const-wide/16 p0, 0x1

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_0
    move-wide p0, v2

    .line 14
    :goto_0
    if-eqz p2, :cond_1

    .line 15
    .line 16
    const-wide/16 v2, 0x2

    .line 17
    .line 18
    :cond_1
    or-long/2addr p0, v2

    .line 19
    const/16 p2, 0x20

    .line 20
    .line 21
    shl-long/2addr v0, p2

    .line 22
    const-wide v2, 0xffffffffL

    .line 23
    .line 24
    .line 25
    .line 26
    .line 27
    and-long/2addr p0, v2

    .line 28
    or-long/2addr p0, v0

    .line 29
    return-wide p0
.end method

.method public static final b(Ln2/b;Lx2/r;)V
    .locals 2

    .line 1
    invoke-static {p1}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p1

    .line 5
    invoke-virtual {p1}, Lv3/h0;->z()Ln2/b;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    iget v0, p1, Ln2/b;->f:I

    .line 10
    .line 11
    add-int/lit8 v0, v0, -0x1

    .line 12
    .line 13
    iget-object p1, p1, Ln2/b;->d:[Ljava/lang/Object;

    .line 14
    .line 15
    array-length v1, p1

    .line 16
    if-ge v0, v1, :cond_0

    .line 17
    .line 18
    :goto_0
    if-ltz v0, :cond_0

    .line 19
    .line 20
    aget-object v1, p1, v0

    .line 21
    .line 22
    check-cast v1, Lv3/h0;

    .line 23
    .line 24
    iget-object v1, v1, Lv3/h0;->H:Lg1/q;

    .line 25
    .line 26
    iget-object v1, v1, Lg1/q;->g:Ljava/lang/Object;

    .line 27
    .line 28
    check-cast v1, Lx2/r;

    .line 29
    .line 30
    invoke-virtual {p0, v1}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 31
    .line 32
    .line 33
    add-int/lit8 v0, v0, -0x1

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    return-void
.end method

.method public static final c(Lv3/p0;Lt3/a;)I
    .locals 4

    .line 1
    invoke-virtual {p0}, Lv3/p0;->H0()Lv3/p0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    new-instance v1, Ljava/lang/StringBuilder;

    .line 9
    .line 10
    const-string v2, "Child of "

    .line 11
    .line 12
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    const-string v2, " cannot be null when calculating alignment line"

    .line 19
    .line 20
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v1

    .line 27
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    invoke-virtual {p0}, Lv3/p0;->N0()Lt3/r0;

    .line 31
    .line 32
    .line 33
    move-result-object v1

    .line 34
    invoke-interface {v1}, Lt3/r0;->b()Ljava/util/Map;

    .line 35
    .line 36
    .line 37
    move-result-object v1

    .line 38
    invoke-interface {v1, p1}, Ljava/util/Map;->containsKey(Ljava/lang/Object;)Z

    .line 39
    .line 40
    .line 41
    move-result v1

    .line 42
    const/high16 v2, -0x80000000

    .line 43
    .line 44
    if-eqz v1, :cond_1

    .line 45
    .line 46
    invoke-virtual {p0}, Lv3/p0;->N0()Lt3/r0;

    .line 47
    .line 48
    .line 49
    move-result-object p0

    .line 50
    invoke-interface {p0}, Lt3/r0;->b()Ljava/util/Map;

    .line 51
    .line 52
    .line 53
    move-result-object p0

    .line 54
    invoke-interface {p0, p1}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 55
    .line 56
    .line 57
    move-result-object p0

    .line 58
    check-cast p0, Ljava/lang/Integer;

    .line 59
    .line 60
    if-eqz p0, :cond_2

    .line 61
    .line 62
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    return p0

    .line 67
    :cond_1
    invoke-virtual {v0, p1}, Lv3/p0;->a0(Lt3/a;)I

    .line 68
    .line 69
    .line 70
    move-result v1

    .line 71
    if-ne v1, v2, :cond_3

    .line 72
    .line 73
    :cond_2
    return v2

    .line 74
    :cond_3
    const/4 v2, 0x1

    .line 75
    iput-boolean v2, v0, Lv3/p0;->m:Z

    .line 76
    .line 77
    iput-boolean v2, p0, Lv3/p0;->n:Z

    .line 78
    .line 79
    invoke-virtual {p0}, Lv3/p0;->T0()V

    .line 80
    .line 81
    .line 82
    const/4 v2, 0x0

    .line 83
    iput-boolean v2, v0, Lv3/p0;->m:Z

    .line 84
    .line 85
    iput-boolean v2, p0, Lv3/p0;->n:Z

    .line 86
    .line 87
    instance-of p0, p1, Lt3/o;

    .line 88
    .line 89
    if-eqz p0, :cond_4

    .line 90
    .line 91
    invoke-virtual {v0}, Lv3/p0;->P0()J

    .line 92
    .line 93
    .line 94
    move-result-wide p0

    .line 95
    const-wide v2, 0xffffffffL

    .line 96
    .line 97
    .line 98
    .line 99
    .line 100
    and-long/2addr p0, v2

    .line 101
    :goto_1
    long-to-int p0, p0

    .line 102
    add-int/2addr v1, p0

    .line 103
    return v1

    .line 104
    :cond_4
    invoke-virtual {v0}, Lv3/p0;->P0()J

    .line 105
    .line 106
    .line 107
    move-result-wide p0

    .line 108
    const/16 v0, 0x20

    .line 109
    .line 110
    shr-long/2addr p0, v0

    .line 111
    goto :goto_1
.end method

.method public static final d(Lv3/c;)Z
    .locals 1

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv3/h0;->H:Lg1/q;

    .line 6
    .line 7
    iget-object p0, p0, Lg1/q;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast p0, Lv3/z1;

    .line 10
    .line 11
    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.node.TailModifierNode"

    .line 12
    .line 13
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-boolean p0, p0, Lv3/z1;->r:Z

    .line 17
    .line 18
    return p0
.end method

.method public static final e(Lv3/m;I)Lx2/r;
    .locals 2

    .line 1
    check-cast p0, Lx2/r;

    .line 2
    .line 3
    iget-object p0, p0, Lx2/r;->d:Lx2/r;

    .line 4
    .line 5
    iget-object p0, p0, Lx2/r;->i:Lx2/r;

    .line 6
    .line 7
    if-nez p0, :cond_0

    .line 8
    .line 9
    goto :goto_1

    .line 10
    :cond_0
    iget v0, p0, Lx2/r;->g:I

    .line 11
    .line 12
    and-int/2addr v0, p1

    .line 13
    if-nez v0, :cond_1

    .line 14
    .line 15
    goto :goto_1

    .line 16
    :cond_1
    :goto_0
    if-eqz p0, :cond_4

    .line 17
    .line 18
    iget v0, p0, Lx2/r;->f:I

    .line 19
    .line 20
    and-int/lit8 v1, v0, 0x2

    .line 21
    .line 22
    if-eqz v1, :cond_2

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_2
    and-int/2addr v0, p1

    .line 26
    if-eqz v0, :cond_3

    .line 27
    .line 28
    return-object p0

    .line 29
    :cond_3
    iget-object p0, p0, Lx2/r;->i:Lx2/r;

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_4
    :goto_1
    const/4 p0, 0x0

    .line 33
    return-object p0
.end method

.method public static final f(Ln2/b;)Lx2/r;
    .locals 1

    .line 1
    if-eqz p0, :cond_1

    .line 2
    .line 3
    iget v0, p0, Ln2/b;->f:I

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    add-int/lit8 v0, v0, -0x1

    .line 9
    .line 10
    invoke-virtual {p0, v0}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    check-cast p0, Lx2/r;

    .line 15
    .line 16
    return-object p0

    .line 17
    :cond_1
    :goto_0
    const/4 p0, 0x0

    .line 18
    return-object p0
.end method

.method public static final g(Lx2/r;)Lv3/y;
    .locals 2

    .line 1
    iget v0, p0, Lx2/r;->f:I

    .line 2
    .line 3
    and-int/lit8 v0, v0, 0x2

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz v0, :cond_3

    .line 7
    .line 8
    instance-of v0, p0, Lv3/y;

    .line 9
    .line 10
    if-eqz v0, :cond_0

    .line 11
    .line 12
    check-cast p0, Lv3/y;

    .line 13
    .line 14
    return-object p0

    .line 15
    :cond_0
    instance-of v0, p0, Lv3/n;

    .line 16
    .line 17
    if-eqz v0, :cond_3

    .line 18
    .line 19
    check-cast p0, Lv3/n;

    .line 20
    .line 21
    iget-object p0, p0, Lv3/n;->s:Lx2/r;

    .line 22
    .line 23
    :goto_0
    if-eqz p0, :cond_3

    .line 24
    .line 25
    instance-of v0, p0, Lv3/y;

    .line 26
    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    check-cast p0, Lv3/y;

    .line 30
    .line 31
    return-object p0

    .line 32
    :cond_1
    instance-of v0, p0, Lv3/n;

    .line 33
    .line 34
    if-eqz v0, :cond_2

    .line 35
    .line 36
    iget v0, p0, Lx2/r;->f:I

    .line 37
    .line 38
    and-int/lit8 v0, v0, 0x2

    .line 39
    .line 40
    if-eqz v0, :cond_2

    .line 41
    .line 42
    check-cast p0, Lv3/n;

    .line 43
    .line 44
    iget-object p0, p0, Lv3/n;->s:Lx2/r;

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_2
    iget-object p0, p0, Lx2/r;->i:Lx2/r;

    .line 48
    .line 49
    goto :goto_0

    .line 50
    :cond_3
    return-object v1
.end method

.method public static final h(JJ)I
    .locals 5

    .line 1
    invoke-static {p0, p1}, Lv3/f;->q(J)Z

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p2, p3}, Lv3/f;->q(J)Z

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    const/4 v2, 0x1

    .line 10
    const/4 v3, -0x1

    .line 11
    if-eq v0, v1, :cond_1

    .line 12
    .line 13
    if-eqz v0, :cond_0

    .line 14
    .line 15
    return v3

    .line 16
    :cond_0
    return v2

    .line 17
    :cond_1
    invoke-static {p0, p1}, Lv3/f;->l(J)F

    .line 18
    .line 19
    .line 20
    move-result v0

    .line 21
    invoke-static {p2, p3}, Lv3/f;->l(J)F

    .line 22
    .line 23
    .line 24
    move-result v1

    .line 25
    sub-float/2addr v0, v1

    .line 26
    invoke-static {v0}, Ljava/lang/Math;->signum(F)F

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    float-to-int v0, v0

    .line 31
    invoke-static {p0, p1}, Lv3/f;->l(J)F

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    invoke-static {p2, p3}, Lv3/f;->l(J)F

    .line 36
    .line 37
    .line 38
    move-result v4

    .line 39
    invoke-static {v1, v4}, Ljava/lang/Math;->min(FF)F

    .line 40
    .line 41
    .line 42
    move-result v1

    .line 43
    const/4 v4, 0x0

    .line 44
    cmpg-float v1, v1, v4

    .line 45
    .line 46
    if-gez v1, :cond_2

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :cond_2
    invoke-static {p0, p1}, Lv3/f;->p(J)Z

    .line 50
    .line 51
    .line 52
    move-result v1

    .line 53
    invoke-static {p2, p3}, Lv3/f;->p(J)Z

    .line 54
    .line 55
    .line 56
    move-result p2

    .line 57
    if-eq v1, p2, :cond_4

    .line 58
    .line 59
    invoke-static {p0, p1}, Lv3/f;->p(J)Z

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    if-eqz p0, :cond_3

    .line 64
    .line 65
    return v3

    .line 66
    :cond_3
    return v2

    .line 67
    :cond_4
    :goto_0
    return v0
.end method

.method public static final i(Lv3/l;Ll2/s1;)Ljava/lang/Object;
    .locals 1

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Lx2/r;

    .line 3
    .line 4
    iget-object v0, v0, Lx2/r;->d:Lx2/r;

    .line 5
    .line 6
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    const-string v0, "Cannot read CompositionLocal because the Modifier node is not currently attached."

    .line 11
    .line 12
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    iget-object p0, p0, Lv3/h0;->D:Ll2/c0;

    .line 20
    .line 21
    check-cast p0, Lt2/g;

    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 24
    .line 25
    .line 26
    invoke-static {p0, p1}, Ll2/b;->q(Ll2/p1;Ll2/s1;)Ljava/lang/Object;

    .line 27
    .line 28
    .line 29
    move-result-object p0

    .line 30
    return-object p0
.end method

.method public static final j(Lv3/c2;)Lv3/c2;
    .locals 10

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Lx2/r;

    .line 3
    .line 4
    iget-object v1, v0, Lx2/r;->d:Lx2/r;

    .line 5
    .line 6
    iget-boolean v1, v1, Lx2/r;->q:Z

    .line 7
    .line 8
    if-nez v1, :cond_0

    .line 9
    .line 10
    const-string v1, "visitAncestors called on an unattached node"

    .line 11
    .line 12
    invoke-static {v1}, Ls3/a;->b(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    iget-object v0, v0, Lx2/r;->d:Lx2/r;

    .line 16
    .line 17
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 18
    .line 19
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 20
    .line 21
    .line 22
    move-result-object v1

    .line 23
    :goto_0
    const/4 v2, 0x0

    .line 24
    if-eqz v1, :cond_b

    .line 25
    .line 26
    iget-object v3, v1, Lv3/h0;->H:Lg1/q;

    .line 27
    .line 28
    iget-object v3, v3, Lg1/q;->g:Ljava/lang/Object;

    .line 29
    .line 30
    check-cast v3, Lx2/r;

    .line 31
    .line 32
    iget v3, v3, Lx2/r;->g:I

    .line 33
    .line 34
    const/high16 v4, 0x40000

    .line 35
    .line 36
    and-int/2addr v3, v4

    .line 37
    if-eqz v3, :cond_9

    .line 38
    .line 39
    :goto_1
    if-eqz v0, :cond_9

    .line 40
    .line 41
    iget v3, v0, Lx2/r;->f:I

    .line 42
    .line 43
    and-int/2addr v3, v4

    .line 44
    if-eqz v3, :cond_8

    .line 45
    .line 46
    move-object v3, v0

    .line 47
    move-object v5, v2

    .line 48
    :goto_2
    if-eqz v3, :cond_8

    .line 49
    .line 50
    instance-of v6, v3, Lv3/c2;

    .line 51
    .line 52
    if-eqz v6, :cond_1

    .line 53
    .line 54
    check-cast v3, Lv3/c2;

    .line 55
    .line 56
    invoke-interface {p0}, Lv3/c2;->g()Ljava/lang/Object;

    .line 57
    .line 58
    .line 59
    move-result-object v6

    .line 60
    invoke-interface {v3}, Lv3/c2;->g()Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    move-result-object v7

    .line 64
    invoke-static {v6, v7}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 65
    .line 66
    .line 67
    move-result v6

    .line 68
    if-eqz v6, :cond_7

    .line 69
    .line 70
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 71
    .line 72
    .line 73
    move-result-object v6

    .line 74
    invoke-virtual {v3}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 75
    .line 76
    .line 77
    move-result-object v7

    .line 78
    if-ne v6, v7, :cond_7

    .line 79
    .line 80
    return-object v3

    .line 81
    :cond_1
    iget v6, v3, Lx2/r;->f:I

    .line 82
    .line 83
    and-int/2addr v6, v4

    .line 84
    if-eqz v6, :cond_7

    .line 85
    .line 86
    instance-of v6, v3, Lv3/n;

    .line 87
    .line 88
    if-eqz v6, :cond_7

    .line 89
    .line 90
    move-object v6, v3

    .line 91
    check-cast v6, Lv3/n;

    .line 92
    .line 93
    iget-object v6, v6, Lv3/n;->s:Lx2/r;

    .line 94
    .line 95
    const/4 v7, 0x0

    .line 96
    :goto_3
    const/4 v8, 0x1

    .line 97
    if-eqz v6, :cond_6

    .line 98
    .line 99
    iget v9, v6, Lx2/r;->f:I

    .line 100
    .line 101
    and-int/2addr v9, v4

    .line 102
    if-eqz v9, :cond_5

    .line 103
    .line 104
    add-int/lit8 v7, v7, 0x1

    .line 105
    .line 106
    if-ne v7, v8, :cond_2

    .line 107
    .line 108
    move-object v3, v6

    .line 109
    goto :goto_4

    .line 110
    :cond_2
    if-nez v5, :cond_3

    .line 111
    .line 112
    new-instance v5, Ln2/b;

    .line 113
    .line 114
    const/16 v8, 0x10

    .line 115
    .line 116
    new-array v8, v8, [Lx2/r;

    .line 117
    .line 118
    invoke-direct {v5, v8}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 119
    .line 120
    .line 121
    :cond_3
    if-eqz v3, :cond_4

    .line 122
    .line 123
    invoke-virtual {v5, v3}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 124
    .line 125
    .line 126
    move-object v3, v2

    .line 127
    :cond_4
    invoke-virtual {v5, v6}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 128
    .line 129
    .line 130
    :cond_5
    :goto_4
    iget-object v6, v6, Lx2/r;->i:Lx2/r;

    .line 131
    .line 132
    goto :goto_3

    .line 133
    :cond_6
    if-ne v7, v8, :cond_7

    .line 134
    .line 135
    goto :goto_2

    .line 136
    :cond_7
    invoke-static {v5}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 137
    .line 138
    .line 139
    move-result-object v3

    .line 140
    goto :goto_2

    .line 141
    :cond_8
    iget-object v0, v0, Lx2/r;->h:Lx2/r;

    .line 142
    .line 143
    goto :goto_1

    .line 144
    :cond_9
    invoke-virtual {v1}, Lv3/h0;->v()Lv3/h0;

    .line 145
    .line 146
    .line 147
    move-result-object v1

    .line 148
    if-eqz v1, :cond_a

    .line 149
    .line 150
    iget-object v0, v1, Lv3/h0;->H:Lg1/q;

    .line 151
    .line 152
    if-eqz v0, :cond_a

    .line 153
    .line 154
    iget-object v0, v0, Lg1/q;->f:Ljava/lang/Object;

    .line 155
    .line 156
    check-cast v0, Lv3/z1;

    .line 157
    .line 158
    goto/16 :goto_0

    .line 159
    .line 160
    :cond_a
    move-object v0, v2

    .line 161
    goto/16 :goto_0

    .line 162
    .line 163
    :cond_b
    return-object v2
.end method

.method public static final k(Lt3/t;)Ljava/util/ArrayList;
    .locals 5

    .line 1
    const-string v0, "null cannot be cast to non-null type androidx.compose.ui.node.MeasureScopeWithLayoutNode"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p0, Lv3/p0;

    .line 7
    .line 8
    invoke-virtual {p0}, Lv3/p0;->M0()Lv3/h0;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    invoke-static {p0}, Lv3/f;->r(Lv3/h0;)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    invoke-virtual {p0}, Lv3/h0;->p()Ljava/util/List;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    new-instance v1, Ljava/util/ArrayList;

    .line 21
    .line 22
    move-object v2, p0

    .line 23
    check-cast v2, Landroidx/collection/j0;

    .line 24
    .line 25
    iget-object v3, v2, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 26
    .line 27
    check-cast v3, Ln2/b;

    .line 28
    .line 29
    iget v3, v3, Ln2/b;->f:I

    .line 30
    .line 31
    invoke-direct {v1, v3}, Ljava/util/ArrayList;-><init>(I)V

    .line 32
    .line 33
    .line 34
    invoke-interface {p0}, Ljava/util/Collection;->size()I

    .line 35
    .line 36
    .line 37
    move-result p0

    .line 38
    const/4 v3, 0x0

    .line 39
    :goto_0
    if-ge v3, p0, :cond_1

    .line 40
    .line 41
    invoke-virtual {v2, v3}, Landroidx/collection/j0;->get(I)Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    check-cast v4, Lv3/h0;

    .line 46
    .line 47
    if-eqz v0, :cond_0

    .line 48
    .line 49
    invoke-virtual {v4}, Lv3/h0;->m()Ljava/util/List;

    .line 50
    .line 51
    .line 52
    move-result-object v4

    .line 53
    goto :goto_1

    .line 54
    :cond_0
    invoke-virtual {v4}, Lv3/h0;->n()Ljava/util/List;

    .line 55
    .line 56
    .line 57
    move-result-object v4

    .line 58
    :goto_1
    invoke-virtual {v1, v4}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 59
    .line 60
    .line 61
    add-int/lit8 v3, v3, 0x1

    .line 62
    .line 63
    goto :goto_0

    .line 64
    :cond_1
    return-object v1
.end method

.method public static final l(J)F
    .locals 1

    .line 1
    const/16 v0, 0x20

    .line 2
    .line 3
    shr-long/2addr p0, v0

    .line 4
    long-to-int p0, p0

    .line 5
    invoke-static {p0}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public static final m(Lv3/p;)V
    .locals 1

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Lx2/r;

    .line 3
    .line 4
    iget-object v0, v0, Lx2/r;->d:Lx2/r;

    .line 5
    .line 6
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 7
    .line 8
    if-eqz v0, :cond_0

    .line 9
    .line 10
    const/4 v0, 0x1

    .line 11
    invoke-static {p0, v0}, Lv3/f;->v(Lv3/m;I)Lv3/f1;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-virtual {p0}, Lv3/f1;->m1()V

    .line 16
    .line 17
    .line 18
    :cond_0
    return-void
.end method

.method public static final n(Lv3/y;)V
    .locals 0

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lv3/h0;->E()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static final o(Lv3/x1;)V
    .locals 0

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Lv3/h0;->G()V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public static final p(J)Z
    .locals 2

    .line 1
    const-wide/16 v0, 0x2

    .line 2
    .line 3
    and-long/2addr p0, v0

    .line 4
    const-wide/16 v0, 0x0

    .line 5
    .line 6
    cmp-long p0, p0, v0

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    return p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0
.end method

.method public static final q(J)Z
    .locals 2

    .line 1
    const-wide/16 v0, 0x1

    .line 2
    .line 3
    and-long/2addr p0, v0

    .line 4
    const-wide/16 v0, 0x0

    .line 5
    .line 6
    cmp-long p0, p0, v0

    .line 7
    .line 8
    if-eqz p0, :cond_0

    .line 9
    .line 10
    const/4 p0, 0x1

    .line 11
    return p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return p0
.end method

.method public static final r(Lv3/h0;)Z
    .locals 3

    .line 1
    iget-object v0, p0, Lv3/h0;->I:Lv3/l0;

    .line 2
    .line 3
    iget-object v0, v0, Lv3/l0;->d:Lv3/d0;

    .line 4
    .line 5
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_3

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    if-eq v0, v1, :cond_2

    .line 13
    .line 14
    const/4 v2, 0x2

    .line 15
    if-eq v0, v2, :cond_3

    .line 16
    .line 17
    const/4 v2, 0x3

    .line 18
    if-eq v0, v2, :cond_2

    .line 19
    .line 20
    const/4 v1, 0x4

    .line 21
    if-ne v0, v1, :cond_1

    .line 22
    .line 23
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    if-eqz p0, :cond_0

    .line 28
    .line 29
    invoke-static {p0}, Lv3/f;->r(Lv3/h0;)Z

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    return p0

    .line 34
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 35
    .line 36
    const-string v0, "no parent for idle node"

    .line 37
    .line 38
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 39
    .line 40
    .line 41
    throw p0

    .line 42
    :cond_1
    new-instance p0, La8/r0;

    .line 43
    .line 44
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 45
    .line 46
    .line 47
    throw p0

    .line 48
    :cond_2
    return v1

    .line 49
    :cond_3
    const/4 p0, 0x0

    .line 50
    return p0
.end method

.method public static final s(Lv3/h0;)Z
    .locals 1

    .line 1
    iget-object v0, p0, Lv3/h0;->j:Lv3/h0;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    invoke-virtual {p0}, Lv3/h0;->v()Lv3/h0;

    .line 6
    .line 7
    .line 8
    move-result-object v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-object v0, v0, Lv3/h0;->j:Lv3/h0;

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 v0, 0x0

    .line 15
    :goto_0
    if-eqz v0, :cond_1

    .line 16
    .line 17
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 18
    .line 19
    iget-boolean p0, p0, Lv3/l0;->b:Z

    .line 20
    .line 21
    if-eqz p0, :cond_2

    .line 22
    .line 23
    :cond_1
    const/4 p0, 0x1

    .line 24
    return p0

    .line 25
    :cond_2
    const/4 p0, 0x0

    .line 26
    return p0
.end method

.method public static final t(Lx2/r;Lay0/a;)V
    .locals 2

    .line 1
    iget-object v0, p0, Lx2/r;->j:Lv3/k1;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lv3/k1;

    .line 6
    .line 7
    move-object v1, p0

    .line 8
    check-cast v1, Lv3/j1;

    .line 9
    .line 10
    invoke-direct {v0, v1}, Lv3/k1;-><init>(Lv3/j1;)V

    .line 11
    .line 12
    .line 13
    iput-object v0, p0, Lx2/r;->j:Lv3/k1;

    .line 14
    .line 15
    :cond_0
    invoke-static {p0}, Lv3/f;->y(Lv3/m;)Lv3/o1;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Lw3/t;

    .line 20
    .line 21
    invoke-virtual {p0}, Lw3/t;->getSnapshotObserver()Lv3/q1;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    sget-object v1, Lv3/e;->k:Lv3/e;

    .line 26
    .line 27
    invoke-virtual {p0, v0, v1, p1}, Lv3/q1;->a(Lv3/p1;Lay0/k;Lay0/a;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method

.method public static final u(Lv3/m;)V
    .locals 5

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-boolean v0, p0, Lv3/h0;->v:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-static {p0}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 11
    .line 12
    .line 13
    move-result-object v0

    .line 14
    check-cast v0, Lw3/t;

    .line 15
    .line 16
    iget-object v0, v0, Lw3/t;->I:Ly2/b;

    .line 17
    .line 18
    if-eqz v0, :cond_1

    .line 19
    .line 20
    iget-object v1, v0, Ly2/b;->d:Le4/a;

    .line 21
    .line 22
    iget-object v1, v1, Le4/a;->a:Lbb/g0;

    .line 23
    .line 24
    iget v2, p0, Lv3/h0;->e:I

    .line 25
    .line 26
    new-instance v3, Ltv/e;

    .line 27
    .line 28
    const/4 v4, 0x2

    .line 29
    invoke-direct {v3, v4, v0, p0}, Ltv/e;-><init>(ILjava/lang/Object;Ljava/lang/Object;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v1, v2, v3}, Lbb/g0;->u(ILay0/p;)V

    .line 33
    .line 34
    .line 35
    :cond_1
    :goto_0
    return-void
.end method

.method public static final v(Lv3/m;I)Lv3/f1;
    .locals 2

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Lx2/r;

    .line 3
    .line 4
    iget-object v0, v0, Lx2/r;->d:Lx2/r;

    .line 5
    .line 6
    iget-object v0, v0, Lx2/r;->k:Lv3/f1;

    .line 7
    .line 8
    invoke-static {v0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    invoke-virtual {v0}, Lv3/f1;->f1()Lx2/r;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    if-eq v1, p0, :cond_0

    .line 16
    .line 17
    goto :goto_0

    .line 18
    :cond_0
    invoke-static {p1}, Lv3/g1;->g(I)Z

    .line 19
    .line 20
    .line 21
    move-result p0

    .line 22
    if-eqz p0, :cond_1

    .line 23
    .line 24
    iget-object p0, v0, Lv3/f1;->s:Lv3/f1;

    .line 25
    .line 26
    invoke-static {p0}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 27
    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_1
    :goto_0
    return-object v0
.end method

.method public static final w(Lv3/m;)Lv3/f1;
    .locals 1

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Lx2/r;

    .line 3
    .line 4
    iget-object v0, v0, Lx2/r;->d:Lx2/r;

    .line 5
    .line 6
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    const-string v0, "Cannot get LayoutCoordinates, Modifier.Node is not attached."

    .line 11
    .line 12
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    const/4 v0, 0x2

    .line 16
    invoke-static {p0, v0}, Lv3/f;->v(Lv3/m;I)Lv3/f1;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {p0}, Lv3/f1;->f1()Lx2/r;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 25
    .line 26
    if-nez v0, :cond_1

    .line 27
    .line 28
    const-string v0, "LayoutCoordinates is not attached."

    .line 29
    .line 30
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    :cond_1
    return-object p0
.end method

.method public static final x(Lv3/m;)Lv3/h0;
    .locals 0

    .line 1
    check-cast p0, Lx2/r;

    .line 2
    .line 3
    iget-object p0, p0, Lx2/r;->d:Lx2/r;

    .line 4
    .line 5
    iget-object p0, p0, Lx2/r;->k:Lv3/f1;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    iget-object p0, p0, Lv3/f1;->r:Lv3/h0;

    .line 10
    .line 11
    return-object p0

    .line 12
    :cond_0
    const-string p0, "Cannot obtain node coordinator. Is the Modifier.Node attached?"

    .line 13
    .line 14
    invoke-static {p0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    throw p0
.end method

.method public static final y(Lv3/m;)Lv3/o1;
    .locals 0

    .line 1
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    iget-object p0, p0, Lv3/h0;->p:Lv3/o1;

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    return-object p0

    .line 10
    :cond_0
    const-string p0, "This node does not have an owner."

    .line 11
    .line 12
    invoke-static {p0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    throw p0
.end method

.method public static final z(Lv3/m;)Landroid/view/View;
    .locals 1

    .line 1
    move-object v0, p0

    .line 2
    check-cast v0, Lx2/r;

    .line 3
    .line 4
    iget-object v0, v0, Lx2/r;->d:Lx2/r;

    .line 5
    .line 6
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 7
    .line 8
    if-nez v0, :cond_0

    .line 9
    .line 10
    const-string v0, "Cannot get View because the Modifier node is not currently attached."

    .line 11
    .line 12
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 13
    .line 14
    .line 15
    :cond_0
    invoke-static {p0}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-static {p0}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    check-cast p0, Landroid/view/View;

    .line 24
    .line 25
    return-object p0
.end method
