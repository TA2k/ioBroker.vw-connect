.class public final Lt3/l0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt3/m1;


# instance fields
.field public final a:Landroidx/collection/c0;

.field public final synthetic b:Lt3/m0;

.field public final synthetic c:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Lt3/m0;Ljava/lang/Object;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lt3/l0;->b:Lt3/m0;

    .line 5
    .line 6
    iput-object p2, p0, Lt3/l0;->c:Ljava/lang/Object;

    .line 7
    .line 8
    sget-object p1, Landroidx/collection/r;->a:[I

    .line 9
    .line 10
    new-instance p1, Landroidx/collection/c0;

    .line 11
    .line 12
    invoke-direct {p1}, Landroidx/collection/c0;-><init>()V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lt3/l0;->a:Landroidx/collection/c0;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a(I)J
    .locals 4

    .line 1
    iget-object v0, p0, Lt3/l0;->b:Lt3/m0;

    .line 2
    .line 3
    iget-object v0, v0, Lt3/m0;->m:Landroidx/collection/q0;

    .line 4
    .line 5
    iget-object v1, p0, Lt3/l0;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-virtual {v0, v1}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    check-cast v0, Lv3/h0;

    .line 12
    .line 13
    if-eqz v0, :cond_2

    .line 14
    .line 15
    invoke-virtual {v0}, Lv3/h0;->I()Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    if-eqz v1, :cond_2

    .line 20
    .line 21
    invoke-virtual {v0}, Lv3/h0;->o()Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    check-cast v1, Landroidx/collection/j0;

    .line 26
    .line 27
    iget-object v1, v1, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v1, Ln2/b;

    .line 30
    .line 31
    iget v1, v1, Ln2/b;->f:I

    .line 32
    .line 33
    if-ltz p1, :cond_0

    .line 34
    .line 35
    if-lt p1, v1, :cond_1

    .line 36
    .line 37
    :cond_0
    new-instance v2, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    const-string v3, "Index ("

    .line 40
    .line 41
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v2, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string v3, ") is out of bound of [0, "

    .line 48
    .line 49
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const/16 v1, 0x29

    .line 56
    .line 57
    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v1

    .line 64
    invoke-static {v1}, Ls3/a;->d(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    :cond_1
    iget-object p0, p0, Lt3/l0;->a:Landroidx/collection/c0;

    .line 68
    .line 69
    invoke-virtual {p0, p1}, Landroidx/collection/c0;->b(I)Z

    .line 70
    .line 71
    .line 72
    move-result p0

    .line 73
    if-eqz p0, :cond_2

    .line 74
    .line 75
    invoke-virtual {v0}, Lv3/h0;->o()Ljava/util/List;

    .line 76
    .line 77
    .line 78
    move-result-object p0

    .line 79
    check-cast p0, Landroidx/collection/j0;

    .line 80
    .line 81
    invoke-virtual {p0, p1}, Landroidx/collection/j0;->get(I)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Lv3/h0;

    .line 86
    .line 87
    iget-object p0, p0, Lv3/h0;->I:Lv3/l0;

    .line 88
    .line 89
    iget-object p0, p0, Lv3/l0;->p:Lv3/y0;

    .line 90
    .line 91
    iget p0, p0, Lt3/e1;->d:I

    .line 92
    .line 93
    invoke-virtual {v0}, Lv3/h0;->o()Ljava/util/List;

    .line 94
    .line 95
    .line 96
    move-result-object v0

    .line 97
    check-cast v0, Landroidx/collection/j0;

    .line 98
    .line 99
    invoke-virtual {v0, p1}, Landroidx/collection/j0;->get(I)Ljava/lang/Object;

    .line 100
    .line 101
    .line 102
    move-result-object p1

    .line 103
    check-cast p1, Lv3/h0;

    .line 104
    .line 105
    iget-object p1, p1, Lv3/h0;->I:Lv3/l0;

    .line 106
    .line 107
    iget-object p1, p1, Lv3/l0;->p:Lv3/y0;

    .line 108
    .line 109
    iget p1, p1, Lt3/e1;->e:I

    .line 110
    .line 111
    int-to-long v0, p0

    .line 112
    const/16 p0, 0x20

    .line 113
    .line 114
    shl-long/2addr v0, p0

    .line 115
    int-to-long p0, p1

    .line 116
    const-wide v2, 0xffffffffL

    .line 117
    .line 118
    .line 119
    .line 120
    .line 121
    and-long/2addr p0, v2

    .line 122
    or-long/2addr p0, v0

    .line 123
    return-wide p0

    .line 124
    :cond_2
    const-wide/16 p0, 0x0

    .line 125
    .line 126
    return-wide p0
.end method

.method public final b()I
    .locals 1

    .line 1
    iget-object v0, p0, Lt3/l0;->b:Lt3/m0;

    .line 2
    .line 3
    iget-object v0, v0, Lt3/m0;->m:Landroidx/collection/q0;

    .line 4
    .line 5
    iget-object p0, p0, Lt3/l0;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-virtual {v0, p0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Lv3/h0;

    .line 12
    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0}, Lv3/h0;->o()Ljava/util/List;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    check-cast p0, Landroidx/collection/j0;

    .line 20
    .line 21
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Ln2/b;

    .line 24
    .line 25
    iget p0, p0, Ln2/b;->f:I

    .line 26
    .line 27
    return p0

    .line 28
    :cond_0
    const/4 p0, 0x0

    .line 29
    return p0
.end method

.method public final c(IJ)V
    .locals 5

    .line 1
    iget-object v0, p0, Lt3/l0;->b:Lt3/m0;

    .line 2
    .line 3
    iget-object v1, v0, Lt3/m0;->m:Landroidx/collection/q0;

    .line 4
    .line 5
    iget-object v2, p0, Lt3/l0;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-virtual {v1, v2}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    check-cast v1, Lv3/h0;

    .line 12
    .line 13
    if-eqz v1, :cond_3

    .line 14
    .line 15
    invoke-virtual {v1}, Lv3/h0;->I()Z

    .line 16
    .line 17
    .line 18
    move-result v2

    .line 19
    if-eqz v2, :cond_3

    .line 20
    .line 21
    invoke-virtual {v1}, Lv3/h0;->o()Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    check-cast v2, Landroidx/collection/j0;

    .line 26
    .line 27
    iget-object v2, v2, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 28
    .line 29
    check-cast v2, Ln2/b;

    .line 30
    .line 31
    iget v2, v2, Ln2/b;->f:I

    .line 32
    .line 33
    if-ltz p1, :cond_0

    .line 34
    .line 35
    if-lt p1, v2, :cond_1

    .line 36
    .line 37
    :cond_0
    new-instance v3, Ljava/lang/StringBuilder;

    .line 38
    .line 39
    const-string v4, "Index ("

    .line 40
    .line 41
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v3, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string v4, ") is out of bound of [0, "

    .line 48
    .line 49
    invoke-virtual {v3, v4}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    const/16 v2, 0x29

    .line 56
    .line 57
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 58
    .line 59
    .line 60
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 61
    .line 62
    .line 63
    move-result-object v2

    .line 64
    invoke-static {v2}, Ls3/a;->d(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    :cond_1
    invoke-virtual {v1}, Lv3/h0;->J()Z

    .line 68
    .line 69
    .line 70
    move-result v2

    .line 71
    if-eqz v2, :cond_2

    .line 72
    .line 73
    const-string v2, "Pre-measure called on node that is not placed"

    .line 74
    .line 75
    invoke-static {v2}, Ls3/a;->a(Ljava/lang/String;)V

    .line 76
    .line 77
    .line 78
    :cond_2
    iget-object v0, v0, Lt3/m0;->d:Lv3/h0;

    .line 79
    .line 80
    const/4 v2, 0x1

    .line 81
    iput-boolean v2, v0, Lv3/h0;->s:Z

    .line 82
    .line 83
    invoke-static {v1}, Lv3/k0;->a(Lv3/h0;)Lv3/o1;

    .line 84
    .line 85
    .line 86
    move-result-object v2

    .line 87
    invoke-virtual {v1}, Lv3/h0;->o()Ljava/util/List;

    .line 88
    .line 89
    .line 90
    move-result-object v1

    .line 91
    check-cast v1, Landroidx/collection/j0;

    .line 92
    .line 93
    invoke-virtual {v1, p1}, Landroidx/collection/j0;->get(I)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v1

    .line 97
    check-cast v1, Lv3/h0;

    .line 98
    .line 99
    check-cast v2, Lw3/t;

    .line 100
    .line 101
    invoke-virtual {v2, v1, p2, p3}, Lw3/t;->s(Lv3/h0;J)V

    .line 102
    .line 103
    .line 104
    const/4 p2, 0x0

    .line 105
    iput-boolean p2, v0, Lv3/h0;->s:Z

    .line 106
    .line 107
    iget-object p0, p0, Lt3/l0;->a:Landroidx/collection/c0;

    .line 108
    .line 109
    invoke-virtual {p0, p1}, Landroidx/collection/c0;->a(I)Z

    .line 110
    .line 111
    .line 112
    :cond_3
    return-void
.end method

.method public final d(Lo1/w0;)V
    .locals 11

    .line 1
    iget-object v0, p0, Lt3/l0;->b:Lt3/m0;

    .line 2
    .line 3
    iget-object v0, v0, Lt3/m0;->m:Landroidx/collection/q0;

    .line 4
    .line 5
    iget-object p0, p0, Lt3/l0;->c:Ljava/lang/Object;

    .line 6
    .line 7
    invoke-virtual {v0, p0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    check-cast p0, Lv3/h0;

    .line 12
    .line 13
    if-eqz p0, :cond_e

    .line 14
    .line 15
    iget-object p0, p0, Lv3/h0;->H:Lg1/q;

    .line 16
    .line 17
    if-eqz p0, :cond_e

    .line 18
    .line 19
    iget-object p0, p0, Lg1/q;->g:Ljava/lang/Object;

    .line 20
    .line 21
    check-cast p0, Lx2/r;

    .line 22
    .line 23
    if-eqz p0, :cond_e

    .line 24
    .line 25
    iget-object v0, p0, Lx2/r;->d:Lx2/r;

    .line 26
    .line 27
    iget-boolean v0, v0, Lx2/r;->q:Z

    .line 28
    .line 29
    if-nez v0, :cond_0

    .line 30
    .line 31
    const-string v0, "visitSubtreeIf called on an unattached node"

    .line 32
    .line 33
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    :cond_0
    new-instance v0, Ln2/b;

    .line 37
    .line 38
    const/16 v1, 0x10

    .line 39
    .line 40
    new-array v2, v1, [Lx2/r;

    .line 41
    .line 42
    invoke-direct {v0, v2}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    iget-object p0, p0, Lx2/r;->d:Lx2/r;

    .line 46
    .line 47
    iget-object v2, p0, Lx2/r;->i:Lx2/r;

    .line 48
    .line 49
    if-nez v2, :cond_1

    .line 50
    .line 51
    invoke-static {v0, p0}, Lv3/f;->b(Ln2/b;Lx2/r;)V

    .line 52
    .line 53
    .line 54
    goto :goto_0

    .line 55
    :cond_1
    invoke-virtual {v0, v2}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 56
    .line 57
    .line 58
    :cond_2
    :goto_0
    iget p0, v0, Ln2/b;->f:I

    .line 59
    .line 60
    if-eqz p0, :cond_e

    .line 61
    .line 62
    add-int/lit8 p0, p0, -0x1

    .line 63
    .line 64
    invoke-virtual {v0, p0}, Ln2/b;->m(I)Ljava/lang/Object;

    .line 65
    .line 66
    .line 67
    move-result-object p0

    .line 68
    check-cast p0, Lx2/r;

    .line 69
    .line 70
    iget v2, p0, Lx2/r;->g:I

    .line 71
    .line 72
    const/high16 v3, 0x40000

    .line 73
    .line 74
    and-int/2addr v2, v3

    .line 75
    if-eqz v2, :cond_d

    .line 76
    .line 77
    move-object v2, p0

    .line 78
    :goto_1
    if-eqz v2, :cond_d

    .line 79
    .line 80
    iget v4, v2, Lx2/r;->f:I

    .line 81
    .line 82
    and-int/2addr v4, v3

    .line 83
    if-eqz v4, :cond_c

    .line 84
    .line 85
    const/4 v4, 0x0

    .line 86
    move-object v5, v2

    .line 87
    move-object v6, v4

    .line 88
    :goto_2
    if-eqz v5, :cond_c

    .line 89
    .line 90
    instance-of v7, v5, Lv3/c2;

    .line 91
    .line 92
    if-eqz v7, :cond_5

    .line 93
    .line 94
    check-cast v5, Lv3/c2;

    .line 95
    .line 96
    invoke-interface {v5}, Lv3/c2;->g()Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    move-result-object v7

    .line 100
    const-string v8, "androidx.compose.foundation.lazy.layout.TraversablePrefetchStateNode"

    .line 101
    .line 102
    invoke-virtual {v8, v7}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 103
    .line 104
    .line 105
    move-result v7

    .line 106
    if-eqz v7, :cond_3

    .line 107
    .line 108
    invoke-virtual {p1, v5}, Lo1/w0;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 109
    .line 110
    .line 111
    sget-object v5, Lv3/b2;->e:Lv3/b2;

    .line 112
    .line 113
    goto :goto_3

    .line 114
    :cond_3
    sget-object v5, Lv3/b2;->d:Lv3/b2;

    .line 115
    .line 116
    :goto_3
    sget-object v7, Lv3/b2;->f:Lv3/b2;

    .line 117
    .line 118
    if-ne v5, v7, :cond_4

    .line 119
    .line 120
    goto :goto_7

    .line 121
    :cond_4
    sget-object v7, Lv3/b2;->e:Lv3/b2;

    .line 122
    .line 123
    if-eq v5, v7, :cond_2

    .line 124
    .line 125
    goto :goto_6

    .line 126
    :cond_5
    iget v7, v5, Lx2/r;->f:I

    .line 127
    .line 128
    and-int/2addr v7, v3

    .line 129
    if-eqz v7, :cond_b

    .line 130
    .line 131
    instance-of v7, v5, Lv3/n;

    .line 132
    .line 133
    if-eqz v7, :cond_b

    .line 134
    .line 135
    move-object v7, v5

    .line 136
    check-cast v7, Lv3/n;

    .line 137
    .line 138
    iget-object v7, v7, Lv3/n;->s:Lx2/r;

    .line 139
    .line 140
    const/4 v8, 0x0

    .line 141
    :goto_4
    const/4 v9, 0x1

    .line 142
    if-eqz v7, :cond_a

    .line 143
    .line 144
    iget v10, v7, Lx2/r;->f:I

    .line 145
    .line 146
    and-int/2addr v10, v3

    .line 147
    if-eqz v10, :cond_9

    .line 148
    .line 149
    add-int/lit8 v8, v8, 0x1

    .line 150
    .line 151
    if-ne v8, v9, :cond_6

    .line 152
    .line 153
    move-object v5, v7

    .line 154
    goto :goto_5

    .line 155
    :cond_6
    if-nez v6, :cond_7

    .line 156
    .line 157
    new-instance v6, Ln2/b;

    .line 158
    .line 159
    new-array v9, v1, [Lx2/r;

    .line 160
    .line 161
    invoke-direct {v6, v9}, Ln2/b;-><init>([Ljava/lang/Object;)V

    .line 162
    .line 163
    .line 164
    :cond_7
    if-eqz v5, :cond_8

    .line 165
    .line 166
    invoke-virtual {v6, v5}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 167
    .line 168
    .line 169
    move-object v5, v4

    .line 170
    :cond_8
    invoke-virtual {v6, v7}, Ln2/b;->c(Ljava/lang/Object;)V

    .line 171
    .line 172
    .line 173
    :cond_9
    :goto_5
    iget-object v7, v7, Lx2/r;->i:Lx2/r;

    .line 174
    .line 175
    goto :goto_4

    .line 176
    :cond_a
    if-ne v8, v9, :cond_b

    .line 177
    .line 178
    goto :goto_2

    .line 179
    :cond_b
    :goto_6
    invoke-static {v6}, Lv3/f;->f(Ln2/b;)Lx2/r;

    .line 180
    .line 181
    .line 182
    move-result-object v5

    .line 183
    goto :goto_2

    .line 184
    :cond_c
    iget-object v2, v2, Lx2/r;->i:Lx2/r;

    .line 185
    .line 186
    goto :goto_1

    .line 187
    :cond_d
    invoke-static {v0, p0}, Lv3/f;->b(Ln2/b;Lx2/r;)V

    .line 188
    .line 189
    .line 190
    goto/16 :goto_0

    .line 191
    .line 192
    :cond_e
    :goto_7
    return-void
.end method

.method public final dispose()V
    .locals 5

    .line 1
    iget-object v0, p0, Lt3/l0;->b:Lt3/m0;

    .line 2
    .line 3
    iget-object v1, v0, Lt3/m0;->d:Lv3/h0;

    .line 4
    .line 5
    invoke-virtual {v0}, Lt3/m0;->d()V

    .line 6
    .line 7
    .line 8
    iget-object v2, v0, Lt3/m0;->m:Landroidx/collection/q0;

    .line 9
    .line 10
    iget-object p0, p0, Lt3/l0;->c:Ljava/lang/Object;

    .line 11
    .line 12
    invoke-virtual {v2, p0}, Landroidx/collection/q0;->k(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    check-cast p0, Lv3/h0;

    .line 17
    .line 18
    if-eqz p0, :cond_3

    .line 19
    .line 20
    iget v2, v0, Lt3/m0;->r:I

    .line 21
    .line 22
    if-lez v2, :cond_0

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    const-string v2, "No pre-composed items to dispose"

    .line 26
    .line 27
    invoke-static {v2}, Ls3/a;->b(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    :goto_0
    invoke-virtual {v1}, Lv3/h0;->p()Ljava/util/List;

    .line 31
    .line 32
    .line 33
    move-result-object v2

    .line 34
    check-cast v2, Landroidx/collection/j0;

    .line 35
    .line 36
    iget-object v2, v2, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 37
    .line 38
    check-cast v2, Ln2/b;

    .line 39
    .line 40
    invoke-virtual {v2, p0}, Ln2/b;->k(Ljava/lang/Object;)I

    .line 41
    .line 42
    .line 43
    move-result v2

    .line 44
    invoke-virtual {v1}, Lv3/h0;->p()Ljava/util/List;

    .line 45
    .line 46
    .line 47
    move-result-object v3

    .line 48
    check-cast v3, Landroidx/collection/j0;

    .line 49
    .line 50
    iget-object v3, v3, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 51
    .line 52
    check-cast v3, Ln2/b;

    .line 53
    .line 54
    iget v3, v3, Ln2/b;->f:I

    .line 55
    .line 56
    iget v4, v0, Lt3/m0;->r:I

    .line 57
    .line 58
    sub-int/2addr v3, v4

    .line 59
    if-lt v2, v3, :cond_1

    .line 60
    .line 61
    goto :goto_1

    .line 62
    :cond_1
    const-string v3, "Item is not in pre-composed item range"

    .line 63
    .line 64
    invoke-static {v3}, Ls3/a;->b(Ljava/lang/String;)V

    .line 65
    .line 66
    .line 67
    :goto_1
    iget v3, v0, Lt3/m0;->q:I

    .line 68
    .line 69
    const/4 v4, 0x1

    .line 70
    add-int/2addr v3, v4

    .line 71
    iput v3, v0, Lt3/m0;->q:I

    .line 72
    .line 73
    iget v3, v0, Lt3/m0;->r:I

    .line 74
    .line 75
    add-int/lit8 v3, v3, -0x1

    .line 76
    .line 77
    iput v3, v0, Lt3/m0;->r:I

    .line 78
    .line 79
    iget-object v3, v0, Lt3/m0;->i:Landroidx/collection/q0;

    .line 80
    .line 81
    invoke-virtual {v3, p0}, Landroidx/collection/q0;->g(Ljava/lang/Object;)Ljava/lang/Object;

    .line 82
    .line 83
    .line 84
    move-result-object p0

    .line 85
    check-cast p0, Lt3/f0;

    .line 86
    .line 87
    if-eqz p0, :cond_2

    .line 88
    .line 89
    invoke-static {p0}, Lt3/m0;->b(Lt3/f0;)V

    .line 90
    .line 91
    .line 92
    :cond_2
    invoke-virtual {v1}, Lv3/h0;->p()Ljava/util/List;

    .line 93
    .line 94
    .line 95
    move-result-object p0

    .line 96
    check-cast p0, Landroidx/collection/j0;

    .line 97
    .line 98
    iget-object p0, p0, Landroidx/collection/j0;->e:Ljava/lang/Object;

    .line 99
    .line 100
    check-cast p0, Ln2/b;

    .line 101
    .line 102
    iget p0, p0, Ln2/b;->f:I

    .line 103
    .line 104
    iget v3, v0, Lt3/m0;->r:I

    .line 105
    .line 106
    sub-int/2addr p0, v3

    .line 107
    iget v3, v0, Lt3/m0;->q:I

    .line 108
    .line 109
    sub-int/2addr p0, v3

    .line 110
    iput-boolean v4, v1, Lv3/h0;->s:Z

    .line 111
    .line 112
    invoke-virtual {v1, v2, p0, v4}, Lv3/h0;->M(III)V

    .line 113
    .line 114
    .line 115
    const/4 v2, 0x0

    .line 116
    iput-boolean v2, v1, Lv3/h0;->s:Z

    .line 117
    .line 118
    invoke-virtual {v0, p0}, Lt3/m0;->c(I)V

    .line 119
    .line 120
    .line 121
    :cond_3
    return-void
.end method
