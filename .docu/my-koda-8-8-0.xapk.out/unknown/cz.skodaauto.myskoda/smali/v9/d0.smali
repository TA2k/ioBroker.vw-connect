.class public final Lv9/d0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lo8/o;


# instance fields
.field public final a:I

.field public final b:Ljava/util/List;

.field public final c:Lw7/p;

.field public final d:Landroid/util/SparseIntArray;

.field public final e:Laq/m;

.field public final f:Ll9/h;

.field public final g:Landroid/util/SparseArray;

.field public final h:Landroid/util/SparseBooleanArray;

.field public final i:Landroid/util/SparseBooleanArray;

.field public final j:Lv9/x;

.field public k:Lt8/b;

.field public l:Lo8/q;

.field public m:I

.field public n:Z

.field public o:Z

.field public p:Z

.field public q:I


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>(ILl9/h;Lw7/u;Laq/m;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lv9/d0;->e:Laq/m;

    .line 5
    .line 6
    iput p1, p0, Lv9/d0;->a:I

    .line 7
    .line 8
    iput-object p2, p0, Lv9/d0;->f:Ll9/h;

    .line 9
    .line 10
    invoke-static {p3}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 11
    .line 12
    .line 13
    move-result-object p1

    .line 14
    iput-object p1, p0, Lv9/d0;->b:Ljava/util/List;

    .line 15
    .line 16
    new-instance p1, Lw7/p;

    .line 17
    .line 18
    const/16 p2, 0x24b8

    .line 19
    .line 20
    new-array p2, p2, [B

    .line 21
    .line 22
    const/4 p3, 0x0

    .line 23
    invoke-direct {p1, p3, p2}, Lw7/p;-><init>(I[B)V

    .line 24
    .line 25
    .line 26
    iput-object p1, p0, Lv9/d0;->c:Lw7/p;

    .line 27
    .line 28
    new-instance p1, Landroid/util/SparseBooleanArray;

    .line 29
    .line 30
    invoke-direct {p1}, Landroid/util/SparseBooleanArray;-><init>()V

    .line 31
    .line 32
    .line 33
    iput-object p1, p0, Lv9/d0;->h:Landroid/util/SparseBooleanArray;

    .line 34
    .line 35
    new-instance p2, Landroid/util/SparseBooleanArray;

    .line 36
    .line 37
    invoke-direct {p2}, Landroid/util/SparseBooleanArray;-><init>()V

    .line 38
    .line 39
    .line 40
    iput-object p2, p0, Lv9/d0;->i:Landroid/util/SparseBooleanArray;

    .line 41
    .line 42
    new-instance p2, Landroid/util/SparseArray;

    .line 43
    .line 44
    invoke-direct {p2}, Landroid/util/SparseArray;-><init>()V

    .line 45
    .line 46
    .line 47
    iput-object p2, p0, Lv9/d0;->g:Landroid/util/SparseArray;

    .line 48
    .line 49
    new-instance p4, Landroid/util/SparseIntArray;

    .line 50
    .line 51
    invoke-direct {p4}, Landroid/util/SparseIntArray;-><init>()V

    .line 52
    .line 53
    .line 54
    iput-object p4, p0, Lv9/d0;->d:Landroid/util/SparseIntArray;

    .line 55
    .line 56
    new-instance p4, Lv9/x;

    .line 57
    .line 58
    const/4 v0, 0x1

    .line 59
    invoke-direct {p4, v0}, Lv9/x;-><init>(I)V

    .line 60
    .line 61
    .line 62
    iput-object p4, p0, Lv9/d0;->j:Lv9/x;

    .line 63
    .line 64
    sget-object p4, Lo8/q;->l1:Lrb0/a;

    .line 65
    .line 66
    iput-object p4, p0, Lv9/d0;->l:Lo8/q;

    .line 67
    .line 68
    const/4 p4, -0x1

    .line 69
    iput p4, p0, Lv9/d0;->q:I

    .line 70
    .line 71
    invoke-virtual {p1}, Landroid/util/SparseBooleanArray;->clear()V

    .line 72
    .line 73
    .line 74
    invoke-virtual {p2}, Landroid/util/SparseArray;->clear()V

    .line 75
    .line 76
    .line 77
    new-instance p1, Landroid/util/SparseArray;

    .line 78
    .line 79
    invoke-direct {p1}, Landroid/util/SparseArray;-><init>()V

    .line 80
    .line 81
    .line 82
    invoke-virtual {p1}, Landroid/util/SparseArray;->size()I

    .line 83
    .line 84
    .line 85
    move-result p4

    .line 86
    move v0, p3

    .line 87
    :goto_0
    if-ge v0, p4, :cond_0

    .line 88
    .line 89
    invoke-virtual {p1, v0}, Landroid/util/SparseArray;->keyAt(I)I

    .line 90
    .line 91
    .line 92
    move-result v1

    .line 93
    invoke-virtual {p1, v0}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 94
    .line 95
    .line 96
    move-result-object v2

    .line 97
    check-cast v2, Lv9/f0;

    .line 98
    .line 99
    invoke-virtual {p2, v1, v2}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    add-int/lit8 v0, v0, 0x1

    .line 103
    .line 104
    goto :goto_0

    .line 105
    :cond_0
    new-instance p1, Lv9/b0;

    .line 106
    .line 107
    new-instance p4, Lb81/b;

    .line 108
    .line 109
    invoke-direct {p4, p0}, Lb81/b;-><init>(Lv9/d0;)V

    .line 110
    .line 111
    .line 112
    invoke-direct {p1, p4}, Lv9/b0;-><init>(Lv9/a0;)V

    .line 113
    .line 114
    .line 115
    invoke-virtual {p2, p3, p1}, Landroid/util/SparseArray;->put(ILjava/lang/Object;)V

    .line 116
    .line 117
    .line 118
    return-void
.end method


# virtual methods
.method public final a(Lo8/p;)Z
    .locals 5

    .line 1
    iget-object p0, p0, Lv9/d0;->c:Lw7/p;

    .line 2
    .line 3
    iget-object p0, p0, Lw7/p;->a:[B

    .line 4
    .line 5
    check-cast p1, Lo8/l;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    const/16 v1, 0x3ac

    .line 9
    .line 10
    invoke-virtual {p1, p0, v0, v1, v0}, Lo8/l;->b([BIIZ)Z

    .line 11
    .line 12
    .line 13
    move v1, v0

    .line 14
    :goto_0
    const/16 v2, 0xbc

    .line 15
    .line 16
    if-ge v1, v2, :cond_2

    .line 17
    .line 18
    move v2, v0

    .line 19
    :goto_1
    const/4 v3, 0x5

    .line 20
    if-ge v2, v3, :cond_1

    .line 21
    .line 22
    mul-int/lit16 v3, v2, 0xbc

    .line 23
    .line 24
    add-int/2addr v3, v1

    .line 25
    aget-byte v3, p0, v3

    .line 26
    .line 27
    const/16 v4, 0x47

    .line 28
    .line 29
    if-eq v3, v4, :cond_0

    .line 30
    .line 31
    add-int/lit8 v1, v1, 0x1

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :cond_0
    add-int/lit8 v2, v2, 0x1

    .line 35
    .line 36
    goto :goto_1

    .line 37
    :cond_1
    invoke-virtual {p1, v1, v0}, Lo8/l;->a(IZ)Z

    .line 38
    .line 39
    .line 40
    const/4 p0, 0x1

    .line 41
    return p0

    .line 42
    :cond_2
    return v0
.end method

.method public final b()V
    .locals 0

    .line 1
    return-void
.end method

.method public final c(Lo8/q;)V
    .locals 2

    .line 1
    iget v0, p0, Lv9/d0;->a:I

    .line 2
    .line 3
    and-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    new-instance v0, La8/b;

    .line 8
    .line 9
    iget-object v1, p0, Lv9/d0;->f:Ll9/h;

    .line 10
    .line 11
    invoke-direct {v0, p1, v1}, La8/b;-><init>(Lo8/q;Ll9/h;)V

    .line 12
    .line 13
    .line 14
    move-object p1, v0

    .line 15
    :cond_0
    iput-object p1, p0, Lv9/d0;->l:Lo8/q;

    .line 16
    .line 17
    return-void
.end method

.method public final d(JJ)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p3

    .line 4
    .line 5
    iget-object v3, v0, Lv9/d0;->g:Landroid/util/SparseArray;

    .line 6
    .line 7
    iget-object v4, v0, Lv9/d0;->b:Ljava/util/List;

    .line 8
    .line 9
    invoke-interface {v4}, Ljava/util/List;->size()I

    .line 10
    .line 11
    .line 12
    move-result v5

    .line 13
    const/4 v6, 0x0

    .line 14
    move v7, v6

    .line 15
    :goto_0
    const-wide/16 v8, 0x0

    .line 16
    .line 17
    if-ge v7, v5, :cond_4

    .line 18
    .line 19
    invoke-interface {v4, v7}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    move-result-object v10

    .line 23
    check-cast v10, Lw7/u;

    .line 24
    .line 25
    monitor-enter v10

    .line 26
    :try_start_0
    iget-wide v11, v10, Lw7/u;->b:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 27
    .line 28
    monitor-exit v10

    .line 29
    const-wide v13, -0x7fffffffffffffffL    # -4.9E-324

    .line 30
    .line 31
    .line 32
    .line 33
    .line 34
    cmp-long v11, v11, v13

    .line 35
    .line 36
    const/4 v12, 0x1

    .line 37
    if-nez v11, :cond_0

    .line 38
    .line 39
    move v11, v12

    .line 40
    goto :goto_1

    .line 41
    :cond_0
    move v11, v6

    .line 42
    :goto_1
    if-nez v11, :cond_2

    .line 43
    .line 44
    invoke-virtual {v10}, Lw7/u;->d()J

    .line 45
    .line 46
    .line 47
    move-result-wide v15

    .line 48
    cmp-long v11, v15, v13

    .line 49
    .line 50
    if-eqz v11, :cond_1

    .line 51
    .line 52
    cmp-long v8, v15, v8

    .line 53
    .line 54
    if-eqz v8, :cond_1

    .line 55
    .line 56
    cmp-long v8, v15, v1

    .line 57
    .line 58
    if-eqz v8, :cond_1

    .line 59
    .line 60
    goto :goto_2

    .line 61
    :cond_1
    move v12, v6

    .line 62
    :goto_2
    move v11, v12

    .line 63
    :cond_2
    if-eqz v11, :cond_3

    .line 64
    .line 65
    invoke-virtual {v10, v1, v2}, Lw7/u;->e(J)V

    .line 66
    .line 67
    .line 68
    :cond_3
    add-int/lit8 v7, v7, 0x1

    .line 69
    .line 70
    goto :goto_0

    .line 71
    :catchall_0
    move-exception v0

    .line 72
    :try_start_1
    monitor-exit v10
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 73
    throw v0

    .line 74
    :cond_4
    cmp-long v4, v1, v8

    .line 75
    .line 76
    if-eqz v4, :cond_5

    .line 77
    .line 78
    iget-object v4, v0, Lv9/d0;->k:Lt8/b;

    .line 79
    .line 80
    if-eqz v4, :cond_5

    .line 81
    .line 82
    invoke-virtual {v4, v1, v2}, Lo8/j;->B(J)V

    .line 83
    .line 84
    .line 85
    :cond_5
    iget-object v1, v0, Lv9/d0;->c:Lw7/p;

    .line 86
    .line 87
    invoke-virtual {v1, v6}, Lw7/p;->F(I)V

    .line 88
    .line 89
    .line 90
    iget-object v0, v0, Lv9/d0;->d:Landroid/util/SparseIntArray;

    .line 91
    .line 92
    invoke-virtual {v0}, Landroid/util/SparseIntArray;->clear()V

    .line 93
    .line 94
    .line 95
    :goto_3
    invoke-virtual {v3}, Landroid/util/SparseArray;->size()I

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    if-ge v6, v0, :cond_6

    .line 100
    .line 101
    invoke-virtual {v3, v6}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 102
    .line 103
    .line 104
    move-result-object v0

    .line 105
    check-cast v0, Lv9/f0;

    .line 106
    .line 107
    invoke-interface {v0}, Lv9/f0;->c()V

    .line 108
    .line 109
    .line 110
    add-int/lit8 v6, v6, 0x1

    .line 111
    .line 112
    goto :goto_3

    .line 113
    :cond_6
    return-void
.end method

.method public final h(Lo8/p;Lo8/s;)I
    .locals 22

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
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 8
    .line 9
    .line 10
    move-result-wide v12

    .line 11
    iget-boolean v3, v0, Lv9/d0;->n:Z

    .line 12
    .line 13
    const/16 v4, 0x47

    .line 14
    .line 15
    const-wide/16 v17, -0x1

    .line 16
    .line 17
    const/4 v5, 0x1

    .line 18
    const/4 v6, 0x0

    .line 19
    if-eqz v3, :cond_14

    .line 20
    .line 21
    cmp-long v3, v12, v17

    .line 22
    .line 23
    const-wide v7, -0x7fffffffffffffffL    # -4.9E-324

    .line 24
    .line 25
    .line 26
    .line 27
    .line 28
    iget-object v9, v0, Lv9/d0;->j:Lv9/x;

    .line 29
    .line 30
    if-eqz v3, :cond_f

    .line 31
    .line 32
    iget-boolean v3, v9, Lv9/x;->d:Z

    .line 33
    .line 34
    if-nez v3, :cond_f

    .line 35
    .line 36
    iget v0, v0, Lv9/d0;->q:I

    .line 37
    .line 38
    iget-object v3, v9, Lv9/x;->b:Lw7/u;

    .line 39
    .line 40
    iget-object v10, v9, Lv9/x;->c:Lw7/p;

    .line 41
    .line 42
    if-gtz v0, :cond_0

    .line 43
    .line 44
    invoke-virtual {v9, v1}, Lv9/x;->a(Lo8/p;)V

    .line 45
    .line 46
    .line 47
    return v6

    .line 48
    :cond_0
    iget-boolean v11, v9, Lv9/x;->f:Z

    .line 49
    .line 50
    const v12, 0x1b8a0

    .line 51
    .line 52
    .line 53
    if-nez v11, :cond_7

    .line 54
    .line 55
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 56
    .line 57
    .line 58
    move-result-wide v13

    .line 59
    int-to-long v11, v12

    .line 60
    invoke-static {v11, v12, v13, v14}, Ljava/lang/Math;->min(JJ)J

    .line 61
    .line 62
    .line 63
    move-result-wide v11

    .line 64
    long-to-int v3, v11

    .line 65
    int-to-long v11, v3

    .line 66
    sub-long/2addr v13, v11

    .line 67
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 68
    .line 69
    .line 70
    move-result-wide v11

    .line 71
    cmp-long v11, v11, v13

    .line 72
    .line 73
    if-eqz v11, :cond_1

    .line 74
    .line 75
    iput-wide v13, v2, Lo8/s;->a:J

    .line 76
    .line 77
    return v5

    .line 78
    :cond_1
    invoke-virtual {v10, v3}, Lw7/p;->F(I)V

    .line 79
    .line 80
    .line 81
    invoke-interface {v1}, Lo8/p;->e()V

    .line 82
    .line 83
    .line 84
    iget-object v2, v10, Lw7/p;->a:[B

    .line 85
    .line 86
    invoke-interface {v1, v2, v6, v3}, Lo8/p;->o([BII)V

    .line 87
    .line 88
    .line 89
    iget v1, v10, Lw7/p;->b:I

    .line 90
    .line 91
    iget v2, v10, Lw7/p;->c:I

    .line 92
    .line 93
    add-int/lit16 v3, v2, -0xbc

    .line 94
    .line 95
    :goto_0
    if-lt v3, v1, :cond_6

    .line 96
    .line 97
    iget-object v11, v10, Lw7/p;->a:[B

    .line 98
    .line 99
    const/4 v12, -0x4

    .line 100
    move v13, v6

    .line 101
    :goto_1
    const/4 v14, 0x4

    .line 102
    if-gt v12, v14, :cond_5

    .line 103
    .line 104
    mul-int/lit16 v14, v12, 0xbc

    .line 105
    .line 106
    add-int/2addr v14, v3

    .line 107
    if-lt v14, v1, :cond_3

    .line 108
    .line 109
    if-ge v14, v2, :cond_3

    .line 110
    .line 111
    aget-byte v14, v11, v14

    .line 112
    .line 113
    if-eq v14, v4, :cond_2

    .line 114
    .line 115
    goto :goto_2

    .line 116
    :cond_2
    add-int/2addr v13, v5

    .line 117
    const/4 v14, 0x5

    .line 118
    if-ne v13, v14, :cond_4

    .line 119
    .line 120
    invoke-static {v10, v3, v0}, Llp/gb;->b(Lw7/p;II)J

    .line 121
    .line 122
    .line 123
    move-result-wide v11

    .line 124
    cmp-long v13, v11, v7

    .line 125
    .line 126
    if-eqz v13, :cond_5

    .line 127
    .line 128
    move-wide v7, v11

    .line 129
    goto :goto_3

    .line 130
    :cond_3
    :goto_2
    move v13, v6

    .line 131
    :cond_4
    add-int/lit8 v12, v12, 0x1

    .line 132
    .line 133
    goto :goto_1

    .line 134
    :cond_5
    add-int/lit8 v3, v3, -0x1

    .line 135
    .line 136
    goto :goto_0

    .line 137
    :cond_6
    :goto_3
    iput-wide v7, v9, Lv9/x;->h:J

    .line 138
    .line 139
    iput-boolean v5, v9, Lv9/x;->f:Z

    .line 140
    .line 141
    return v6

    .line 142
    :cond_7
    iget-wide v13, v9, Lv9/x;->h:J

    .line 143
    .line 144
    cmp-long v11, v13, v7

    .line 145
    .line 146
    if-nez v11, :cond_8

    .line 147
    .line 148
    invoke-virtual {v9, v1}, Lv9/x;->a(Lo8/p;)V

    .line 149
    .line 150
    .line 151
    return v6

    .line 152
    :cond_8
    iget-boolean v11, v9, Lv9/x;->e:Z

    .line 153
    .line 154
    if-nez v11, :cond_d

    .line 155
    .line 156
    int-to-long v11, v12

    .line 157
    invoke-interface {v1}, Lo8/p;->getLength()J

    .line 158
    .line 159
    .line 160
    move-result-wide v13

    .line 161
    invoke-static {v11, v12, v13, v14}, Ljava/lang/Math;->min(JJ)J

    .line 162
    .line 163
    .line 164
    move-result-wide v11

    .line 165
    long-to-int v3, v11

    .line 166
    invoke-interface {v1}, Lo8/p;->getPosition()J

    .line 167
    .line 168
    .line 169
    move-result-wide v11

    .line 170
    int-to-long v13, v6

    .line 171
    cmp-long v11, v11, v13

    .line 172
    .line 173
    if-eqz v11, :cond_9

    .line 174
    .line 175
    iput-wide v13, v2, Lo8/s;->a:J

    .line 176
    .line 177
    return v5

    .line 178
    :cond_9
    invoke-virtual {v10, v3}, Lw7/p;->F(I)V

    .line 179
    .line 180
    .line 181
    invoke-interface {v1}, Lo8/p;->e()V

    .line 182
    .line 183
    .line 184
    iget-object v2, v10, Lw7/p;->a:[B

    .line 185
    .line 186
    invoke-interface {v1, v2, v6, v3}, Lo8/p;->o([BII)V

    .line 187
    .line 188
    .line 189
    iget v1, v10, Lw7/p;->b:I

    .line 190
    .line 191
    iget v2, v10, Lw7/p;->c:I

    .line 192
    .line 193
    :goto_4
    if-ge v1, v2, :cond_c

    .line 194
    .line 195
    iget-object v3, v10, Lw7/p;->a:[B

    .line 196
    .line 197
    aget-byte v3, v3, v1

    .line 198
    .line 199
    if-eq v3, v4, :cond_a

    .line 200
    .line 201
    goto :goto_5

    .line 202
    :cond_a
    invoke-static {v10, v1, v0}, Llp/gb;->b(Lw7/p;II)J

    .line 203
    .line 204
    .line 205
    move-result-wide v11

    .line 206
    cmp-long v3, v11, v7

    .line 207
    .line 208
    if-eqz v3, :cond_b

    .line 209
    .line 210
    move-wide v7, v11

    .line 211
    goto :goto_6

    .line 212
    :cond_b
    :goto_5
    add-int/lit8 v1, v1, 0x1

    .line 213
    .line 214
    goto :goto_4

    .line 215
    :cond_c
    :goto_6
    iput-wide v7, v9, Lv9/x;->g:J

    .line 216
    .line 217
    iput-boolean v5, v9, Lv9/x;->e:Z

    .line 218
    .line 219
    return v6

    .line 220
    :cond_d
    iget-wide v4, v9, Lv9/x;->g:J

    .line 221
    .line 222
    cmp-long v0, v4, v7

    .line 223
    .line 224
    if-nez v0, :cond_e

    .line 225
    .line 226
    invoke-virtual {v9, v1}, Lv9/x;->a(Lo8/p;)V

    .line 227
    .line 228
    .line 229
    return v6

    .line 230
    :cond_e
    invoke-virtual {v3, v4, v5}, Lw7/u;->b(J)J

    .line 231
    .line 232
    .line 233
    move-result-wide v4

    .line 234
    iget-wide v7, v9, Lv9/x;->h:J

    .line 235
    .line 236
    invoke-virtual {v3, v7, v8}, Lw7/u;->c(J)J

    .line 237
    .line 238
    .line 239
    move-result-wide v2

    .line 240
    sub-long/2addr v2, v4

    .line 241
    iput-wide v2, v9, Lv9/x;->i:J

    .line 242
    .line 243
    invoke-virtual {v9, v1}, Lv9/x;->a(Lo8/p;)V

    .line 244
    .line 245
    .line 246
    return v6

    .line 247
    :cond_f
    iget-boolean v3, v0, Lv9/d0;->o:Z

    .line 248
    .line 249
    if-nez v3, :cond_11

    .line 250
    .line 251
    iput-boolean v5, v0, Lv9/d0;->o:Z

    .line 252
    .line 253
    move v3, v6

    .line 254
    move-wide v10, v7

    .line 255
    iget-wide v6, v9, Lv9/x;->i:J

    .line 256
    .line 257
    cmp-long v8, v6, v10

    .line 258
    .line 259
    if-eqz v8, :cond_10

    .line 260
    .line 261
    move v8, v3

    .line 262
    new-instance v3, Lt8/b;

    .line 263
    .line 264
    iget-object v9, v9, Lv9/x;->b:Lw7/u;

    .line 265
    .line 266
    iget v10, v0, Lv9/d0;->q:I

    .line 267
    .line 268
    move v11, v4

    .line 269
    new-instance v4, Lpy/a;

    .line 270
    .line 271
    const/16 v14, 0xa

    .line 272
    .line 273
    invoke-direct {v4, v14}, Lpy/a;-><init>(I)V

    .line 274
    .line 275
    .line 276
    move v14, v5

    .line 277
    new-instance v5, Lbb/g0;

    .line 278
    .line 279
    invoke-direct {v5, v10, v9}, Lbb/g0;-><init>(ILw7/u;)V

    .line 280
    .line 281
    .line 282
    const-wide/16 v9, 0x1

    .line 283
    .line 284
    add-long/2addr v9, v6

    .line 285
    move/from16 v16, v14

    .line 286
    .line 287
    const-wide/16 v14, 0xbc

    .line 288
    .line 289
    move/from16 v19, v16

    .line 290
    .line 291
    const/16 v16, 0x3ac

    .line 292
    .line 293
    move/from16 v21, v8

    .line 294
    .line 295
    move-wide v8, v9

    .line 296
    move/from16 v20, v11

    .line 297
    .line 298
    const-wide/16 v10, 0x0

    .line 299
    .line 300
    move/from16 v1, v21

    .line 301
    .line 302
    invoke-direct/range {v3 .. v16}, Lo8/j;-><init>(Lo8/g;Lo8/i;JJJJJI)V

    .line 303
    .line 304
    .line 305
    iput-object v3, v0, Lv9/d0;->k:Lt8/b;

    .line 306
    .line 307
    iget-object v4, v0, Lv9/d0;->l:Lo8/q;

    .line 308
    .line 309
    iget-object v3, v3, Lo8/j;->c:Ljava/lang/Object;

    .line 310
    .line 311
    check-cast v3, Lo8/e;

    .line 312
    .line 313
    invoke-interface {v4, v3}, Lo8/q;->c(Lo8/c0;)V

    .line 314
    .line 315
    .line 316
    goto :goto_7

    .line 317
    :cond_10
    move v1, v3

    .line 318
    move/from16 v19, v5

    .line 319
    .line 320
    iget-object v3, v0, Lv9/d0;->l:Lo8/q;

    .line 321
    .line 322
    new-instance v4, Lo8/t;

    .line 323
    .line 324
    invoke-direct {v4, v6, v7}, Lo8/t;-><init>(J)V

    .line 325
    .line 326
    .line 327
    invoke-interface {v3, v4}, Lo8/q;->c(Lo8/c0;)V

    .line 328
    .line 329
    .line 330
    goto :goto_7

    .line 331
    :cond_11
    move/from16 v19, v5

    .line 332
    .line 333
    move v1, v6

    .line 334
    :goto_7
    iget-boolean v3, v0, Lv9/d0;->p:Z

    .line 335
    .line 336
    if-eqz v3, :cond_12

    .line 337
    .line 338
    iput-boolean v1, v0, Lv9/d0;->p:Z

    .line 339
    .line 340
    const-wide/16 v3, 0x0

    .line 341
    .line 342
    invoke-virtual {v0, v3, v4, v3, v4}, Lv9/d0;->d(JJ)V

    .line 343
    .line 344
    .line 345
    invoke-interface/range {p1 .. p1}, Lo8/p;->getPosition()J

    .line 346
    .line 347
    .line 348
    move-result-wide v5

    .line 349
    cmp-long v5, v5, v3

    .line 350
    .line 351
    if-eqz v5, :cond_12

    .line 352
    .line 353
    iput-wide v3, v2, Lo8/s;->a:J

    .line 354
    .line 355
    return v19

    .line 356
    :cond_12
    iget-object v3, v0, Lv9/d0;->k:Lt8/b;

    .line 357
    .line 358
    if-eqz v3, :cond_13

    .line 359
    .line 360
    iget-object v4, v3, Lo8/j;->e:Ljava/lang/Object;

    .line 361
    .line 362
    check-cast v4, Lo8/f;

    .line 363
    .line 364
    if-eqz v4, :cond_13

    .line 365
    .line 366
    move-object/from16 v4, p1

    .line 367
    .line 368
    invoke-virtual {v3, v4, v2}, Lo8/j;->u(Lo8/p;Lo8/s;)I

    .line 369
    .line 370
    .line 371
    move-result v0

    .line 372
    return v0

    .line 373
    :cond_13
    move-object/from16 v4, p1

    .line 374
    .line 375
    goto :goto_8

    .line 376
    :cond_14
    move-object v4, v1

    .line 377
    move/from16 v19, v5

    .line 378
    .line 379
    move v1, v6

    .line 380
    :goto_8
    iget-object v2, v0, Lv9/d0;->c:Lw7/p;

    .line 381
    .line 382
    iget-object v3, v2, Lw7/p;->a:[B

    .line 383
    .line 384
    iget v5, v2, Lw7/p;->b:I

    .line 385
    .line 386
    rsub-int v5, v5, 0x24b8

    .line 387
    .line 388
    const/16 v6, 0xbc

    .line 389
    .line 390
    if-ge v5, v6, :cond_16

    .line 391
    .line 392
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 393
    .line 394
    .line 395
    move-result v5

    .line 396
    if-lez v5, :cond_15

    .line 397
    .line 398
    iget v7, v2, Lw7/p;->b:I

    .line 399
    .line 400
    invoke-static {v3, v7, v3, v1, v5}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    .line 401
    .line 402
    .line 403
    :cond_15
    invoke-virtual {v2, v5, v3}, Lw7/p;->G(I[B)V

    .line 404
    .line 405
    .line 406
    :cond_16
    :goto_9
    invoke-virtual {v2}, Lw7/p;->a()I

    .line 407
    .line 408
    .line 409
    move-result v5

    .line 410
    iget-object v7, v0, Lv9/d0;->g:Landroid/util/SparseArray;

    .line 411
    .line 412
    if-ge v5, v6, :cond_1a

    .line 413
    .line 414
    iget v5, v2, Lw7/p;->c:I

    .line 415
    .line 416
    rsub-int v8, v5, 0x24b8

    .line 417
    .line 418
    invoke-interface {v4, v3, v5, v8}, Lt7/g;->read([BII)I

    .line 419
    .line 420
    .line 421
    move-result v8

    .line 422
    const/4 v9, -0x1

    .line 423
    if-ne v8, v9, :cond_19

    .line 424
    .line 425
    move v6, v1

    .line 426
    :goto_a
    invoke-virtual {v7}, Landroid/util/SparseArray;->size()I

    .line 427
    .line 428
    .line 429
    move-result v0

    .line 430
    if-ge v6, v0, :cond_18

    .line 431
    .line 432
    invoke-virtual {v7, v6}, Landroid/util/SparseArray;->valueAt(I)Ljava/lang/Object;

    .line 433
    .line 434
    .line 435
    move-result-object v0

    .line 436
    check-cast v0, Lv9/f0;

    .line 437
    .line 438
    instance-of v1, v0, Lv9/w;

    .line 439
    .line 440
    if-eqz v1, :cond_17

    .line 441
    .line 442
    check-cast v0, Lv9/w;

    .line 443
    .line 444
    iget v1, v0, Lv9/w;->c:I

    .line 445
    .line 446
    const/4 v2, 0x3

    .line 447
    if-ne v1, v2, :cond_17

    .line 448
    .line 449
    iget v1, v0, Lv9/w;->j:I

    .line 450
    .line 451
    if-ne v1, v9, :cond_17

    .line 452
    .line 453
    new-instance v1, Lw7/p;

    .line 454
    .line 455
    invoke-direct {v1}, Lw7/p;-><init>()V

    .line 456
    .line 457
    .line 458
    move/from16 v14, v19

    .line 459
    .line 460
    invoke-virtual {v0, v14, v1}, Lv9/w;->b(ILw7/p;)V

    .line 461
    .line 462
    .line 463
    :cond_17
    add-int/lit8 v6, v6, 0x1

    .line 464
    .line 465
    const/16 v19, 0x1

    .line 466
    .line 467
    goto :goto_a

    .line 468
    :cond_18
    return v9

    .line 469
    :cond_19
    add-int/2addr v5, v8

    .line 470
    invoke-virtual {v2, v5}, Lw7/p;->H(I)V

    .line 471
    .line 472
    .line 473
    const/16 v19, 0x1

    .line 474
    .line 475
    goto :goto_9

    .line 476
    :cond_1a
    iget v3, v2, Lw7/p;->b:I

    .line 477
    .line 478
    iget v4, v2, Lw7/p;->c:I

    .line 479
    .line 480
    iget-object v5, v2, Lw7/p;->a:[B

    .line 481
    .line 482
    :goto_b
    if-ge v3, v4, :cond_1b

    .line 483
    .line 484
    aget-byte v8, v5, v3

    .line 485
    .line 486
    const/16 v11, 0x47

    .line 487
    .line 488
    if-eq v8, v11, :cond_1b

    .line 489
    .line 490
    add-int/lit8 v3, v3, 0x1

    .line 491
    .line 492
    goto :goto_b

    .line 493
    :cond_1b
    invoke-virtual {v2, v3}, Lw7/p;->I(I)V

    .line 494
    .line 495
    .line 496
    add-int/2addr v3, v6

    .line 497
    iget v4, v2, Lw7/p;->c:I

    .line 498
    .line 499
    if-le v3, v4, :cond_1c

    .line 500
    .line 501
    return v1

    .line 502
    :cond_1c
    invoke-virtual {v2}, Lw7/p;->j()I

    .line 503
    .line 504
    .line 505
    move-result v5

    .line 506
    const/high16 v6, 0x800000

    .line 507
    .line 508
    and-int/2addr v6, v5

    .line 509
    if-eqz v6, :cond_1d

    .line 510
    .line 511
    invoke-virtual {v2, v3}, Lw7/p;->I(I)V

    .line 512
    .line 513
    .line 514
    return v1

    .line 515
    :cond_1d
    const/high16 v6, 0x400000

    .line 516
    .line 517
    and-int/2addr v6, v5

    .line 518
    if-eqz v6, :cond_1e

    .line 519
    .line 520
    const/4 v6, 0x1

    .line 521
    goto :goto_c

    .line 522
    :cond_1e
    move v6, v1

    .line 523
    :goto_c
    const v8, 0x1fff00

    .line 524
    .line 525
    .line 526
    and-int/2addr v8, v5

    .line 527
    shr-int/lit8 v8, v8, 0x8

    .line 528
    .line 529
    and-int/lit8 v9, v5, 0x20

    .line 530
    .line 531
    if-eqz v9, :cond_1f

    .line 532
    .line 533
    const/4 v9, 0x1

    .line 534
    goto :goto_d

    .line 535
    :cond_1f
    move v9, v1

    .line 536
    :goto_d
    and-int/lit8 v10, v5, 0x10

    .line 537
    .line 538
    if-eqz v10, :cond_20

    .line 539
    .line 540
    invoke-virtual {v7, v8}, Landroid/util/SparseArray;->get(I)Ljava/lang/Object;

    .line 541
    .line 542
    .line 543
    move-result-object v7

    .line 544
    check-cast v7, Lv9/f0;

    .line 545
    .line 546
    goto :goto_e

    .line 547
    :cond_20
    const/4 v7, 0x0

    .line 548
    :goto_e
    if-nez v7, :cond_21

    .line 549
    .line 550
    invoke-virtual {v2, v3}, Lw7/p;->I(I)V

    .line 551
    .line 552
    .line 553
    return v1

    .line 554
    :cond_21
    and-int/lit8 v5, v5, 0xf

    .line 555
    .line 556
    add-int/lit8 v10, v5, -0x1

    .line 557
    .line 558
    iget-object v11, v0, Lv9/d0;->d:Landroid/util/SparseIntArray;

    .line 559
    .line 560
    invoke-virtual {v11, v8, v10}, Landroid/util/SparseIntArray;->get(II)I

    .line 561
    .line 562
    .line 563
    move-result v10

    .line 564
    invoke-virtual {v11, v8, v5}, Landroid/util/SparseIntArray;->put(II)V

    .line 565
    .line 566
    .line 567
    if-ne v10, v5, :cond_22

    .line 568
    .line 569
    invoke-virtual {v2, v3}, Lw7/p;->I(I)V

    .line 570
    .line 571
    .line 572
    return v1

    .line 573
    :cond_22
    const/16 v19, 0x1

    .line 574
    .line 575
    add-int/lit8 v10, v10, 0x1

    .line 576
    .line 577
    and-int/lit8 v10, v10, 0xf

    .line 578
    .line 579
    if-eq v5, v10, :cond_23

    .line 580
    .line 581
    invoke-interface {v7}, Lv9/f0;->c()V

    .line 582
    .line 583
    .line 584
    :cond_23
    if-eqz v9, :cond_25

    .line 585
    .line 586
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 587
    .line 588
    .line 589
    move-result v5

    .line 590
    invoke-virtual {v2}, Lw7/p;->w()I

    .line 591
    .line 592
    .line 593
    move-result v9

    .line 594
    and-int/lit8 v9, v9, 0x40

    .line 595
    .line 596
    if-eqz v9, :cond_24

    .line 597
    .line 598
    const/4 v9, 0x2

    .line 599
    goto :goto_f

    .line 600
    :cond_24
    move v9, v1

    .line 601
    :goto_f
    or-int/2addr v6, v9

    .line 602
    const/16 v19, 0x1

    .line 603
    .line 604
    add-int/lit8 v5, v5, -0x1

    .line 605
    .line 606
    invoke-virtual {v2, v5}, Lw7/p;->J(I)V

    .line 607
    .line 608
    .line 609
    :cond_25
    iget-boolean v5, v0, Lv9/d0;->n:Z

    .line 610
    .line 611
    if-nez v5, :cond_26

    .line 612
    .line 613
    iget-object v9, v0, Lv9/d0;->i:Landroid/util/SparseBooleanArray;

    .line 614
    .line 615
    invoke-virtual {v9, v8, v1}, Landroid/util/SparseBooleanArray;->get(IZ)Z

    .line 616
    .line 617
    .line 618
    move-result v8

    .line 619
    if-nez v8, :cond_27

    .line 620
    .line 621
    :cond_26
    invoke-virtual {v2, v3}, Lw7/p;->H(I)V

    .line 622
    .line 623
    .line 624
    invoke-interface {v7, v6, v2}, Lv9/f0;->b(ILw7/p;)V

    .line 625
    .line 626
    .line 627
    invoke-virtual {v2, v4}, Lw7/p;->H(I)V

    .line 628
    .line 629
    .line 630
    :cond_27
    if-nez v5, :cond_28

    .line 631
    .line 632
    iget-boolean v4, v0, Lv9/d0;->n:Z

    .line 633
    .line 634
    if-eqz v4, :cond_28

    .line 635
    .line 636
    cmp-long v4, v12, v17

    .line 637
    .line 638
    if-eqz v4, :cond_28

    .line 639
    .line 640
    const/4 v14, 0x1

    .line 641
    iput-boolean v14, v0, Lv9/d0;->p:Z

    .line 642
    .line 643
    :cond_28
    invoke-virtual {v2, v3}, Lw7/p;->I(I)V

    .line 644
    .line 645
    .line 646
    return v1
.end method
