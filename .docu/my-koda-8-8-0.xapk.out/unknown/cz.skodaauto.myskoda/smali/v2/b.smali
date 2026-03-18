.class public Lv2/b;
.super Lv2/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final n:[I


# instance fields
.field public final e:Lay0/k;

.field public final f:Lay0/k;

.field public g:I

.field public h:Landroidx/collection/r0;

.field public i:Ljava/util/ArrayList;

.field public j:Lv2/j;

.field public k:[I

.field public l:I

.field public m:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [I

    .line 3
    .line 4
    sput-object v0, Lv2/b;->n:[I

    .line 5
    .line 6
    return-void
.end method

.method public constructor <init>(JLv2/j;Lay0/k;Lay0/k;)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lv2/f;-><init>(JLv2/j;)V

    .line 2
    .line 3
    .line 4
    iput-object p4, p0, Lv2/b;->e:Lay0/k;

    .line 5
    .line 6
    iput-object p5, p0, Lv2/b;->f:Lay0/k;

    .line 7
    .line 8
    sget-object p1, Lv2/j;->h:Lv2/j;

    .line 9
    .line 10
    iput-object p1, p0, Lv2/b;->j:Lv2/j;

    .line 11
    .line 12
    sget-object p1, Lv2/b;->n:[I

    .line 13
    .line 14
    iput-object p1, p0, Lv2/b;->k:[I

    .line 15
    .line 16
    const/4 p1, 0x1

    .line 17
    iput p1, p0, Lv2/b;->l:I

    .line 18
    .line 19
    return-void
.end method


# virtual methods
.method public final A(J)V
    .locals 2

    .line 1
    sget-object v0, Lv2/l;->c:Ljava/lang/Object;

    .line 2
    .line 3
    monitor-enter v0

    .line 4
    :try_start_0
    iget-object v1, p0, Lv2/b;->j:Lv2/j;

    .line 5
    .line 6
    invoke-virtual {v1, p1, p2}, Lv2/j;->k(J)Lv2/j;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lv2/b;->j:Lv2/j;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 11
    .line 12
    monitor-exit v0

    .line 13
    return-void

    .line 14
    :catchall_0
    move-exception p0

    .line 15
    monitor-exit v0

    .line 16
    throw p0
.end method

.method public B(Landroidx/collection/r0;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lv2/b;->h:Landroidx/collection/r0;

    .line 2
    .line 3
    return-void
.end method

.method public C(Lay0/k;Lay0/k;)Lv2/b;
    .locals 11

    .line 1
    iget-boolean v0, p0, Lv2/f;->c:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const-string v0, "Cannot use a disposed snapshot"

    .line 6
    .line 7
    invoke-static {v0}, Ll2/q1;->a(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-boolean v0, p0, Lv2/b;->m:Z

    .line 11
    .line 12
    if-eqz v0, :cond_2

    .line 13
    .line 14
    iget v0, p0, Lv2/f;->d:I

    .line 15
    .line 16
    if-ltz v0, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    const-string v0, "Unsupported operation on a disposed or applied snapshot"

    .line 20
    .line 21
    invoke-static {v0}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    :cond_2
    :goto_0
    invoke-virtual {p0}, Lv2/f;->g()J

    .line 25
    .line 26
    .line 27
    move-result-wide v0

    .line 28
    invoke-virtual {p0, v0, v1}, Lv2/b;->A(J)V

    .line 29
    .line 30
    .line 31
    sget-object v1, Lv2/l;->c:Ljava/lang/Object;

    .line 32
    .line 33
    monitor-enter v1

    .line 34
    :try_start_0
    sget-wide v3, Lv2/l;->e:J

    .line 35
    .line 36
    const/4 v0, 0x1

    .line 37
    int-to-long v9, v0

    .line 38
    add-long v5, v3, v9

    .line 39
    .line 40
    sput-wide v5, Lv2/l;->e:J

    .line 41
    .line 42
    sget-object v2, Lv2/l;->d:Lv2/j;

    .line 43
    .line 44
    invoke-virtual {v2, v3, v4}, Lv2/j;->k(J)Lv2/j;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    sput-object v2, Lv2/l;->d:Lv2/j;

    .line 49
    .line 50
    invoke-virtual {p0}, Lv2/f;->d()Lv2/j;

    .line 51
    .line 52
    .line 53
    move-result-object v2

    .line 54
    invoke-virtual {v2, v3, v4}, Lv2/j;->k(J)Lv2/j;

    .line 55
    .line 56
    .line 57
    move-result-object v5

    .line 58
    invoke-virtual {p0, v5}, Lv2/f;->r(Lv2/j;)V

    .line 59
    .line 60
    .line 61
    move-object v5, v2

    .line 62
    new-instance v2, Lv2/c;

    .line 63
    .line 64
    invoke-virtual {p0}, Lv2/f;->g()J

    .line 65
    .line 66
    .line 67
    move-result-wide v6

    .line 68
    add-long/2addr v6, v9

    .line 69
    invoke-static {v5, v6, v7, v3, v4}, Lv2/l;->e(Lv2/j;JJ)Lv2/j;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    invoke-virtual {p0}, Lv2/b;->y()Lay0/k;

    .line 74
    .line 75
    .line 76
    move-result-object v6

    .line 77
    invoke-static {p1, v6, v0}, Lv2/l;->l(Lay0/k;Lay0/k;Z)Lay0/k;

    .line 78
    .line 79
    .line 80
    move-result-object v6

    .line 81
    invoke-virtual {p0}, Lv2/b;->i()Lay0/k;

    .line 82
    .line 83
    .line 84
    move-result-object p1

    .line 85
    invoke-static {p2, p1}, Lv2/l;->b(Lay0/k;Lay0/k;)Lay0/k;

    .line 86
    .line 87
    .line 88
    move-result-object v7

    .line 89
    move-object v8, p0

    .line 90
    invoke-direct/range {v2 .. v8}, Lv2/c;-><init>(JLv2/j;Lay0/k;Lay0/k;Lv2/b;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 91
    .line 92
    .line 93
    monitor-exit v1

    .line 94
    iget-boolean p0, v8, Lv2/b;->m:Z

    .line 95
    .line 96
    if-nez p0, :cond_3

    .line 97
    .line 98
    iget-boolean p0, v8, Lv2/f;->c:Z

    .line 99
    .line 100
    if-nez p0, :cond_3

    .line 101
    .line 102
    invoke-virtual {v8}, Lv2/f;->g()J

    .line 103
    .line 104
    .line 105
    move-result-wide p0

    .line 106
    monitor-enter v1

    .line 107
    :try_start_1
    sget-wide v3, Lv2/l;->e:J

    .line 108
    .line 109
    add-long v5, v3, v9

    .line 110
    .line 111
    sput-wide v5, Lv2/l;->e:J

    .line 112
    .line 113
    invoke-virtual {v8, v3, v4}, Lv2/f;->s(J)V

    .line 114
    .line 115
    .line 116
    sget-object p2, Lv2/l;->d:Lv2/j;

    .line 117
    .line 118
    invoke-virtual {v8}, Lv2/f;->g()J

    .line 119
    .line 120
    .line 121
    move-result-wide v3

    .line 122
    invoke-virtual {p2, v3, v4}, Lv2/j;->k(J)Lv2/j;

    .line 123
    .line 124
    .line 125
    move-result-object p2

    .line 126
    sput-object p2, Lv2/l;->d:Lv2/j;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 127
    .line 128
    monitor-exit v1

    .line 129
    invoke-virtual {v8}, Lv2/f;->d()Lv2/j;

    .line 130
    .line 131
    .line 132
    move-result-object p2

    .line 133
    add-long/2addr p0, v9

    .line 134
    invoke-virtual {v8}, Lv2/f;->g()J

    .line 135
    .line 136
    .line 137
    move-result-wide v0

    .line 138
    invoke-static {p2, p0, p1, v0, v1}, Lv2/l;->e(Lv2/j;JJ)Lv2/j;

    .line 139
    .line 140
    .line 141
    move-result-object p0

    .line 142
    invoke-virtual {v8, p0}, Lv2/f;->r(Lv2/j;)V

    .line 143
    .line 144
    .line 145
    return-object v2

    .line 146
    :catchall_0
    move-exception v0

    .line 147
    move-object p0, v0

    .line 148
    monitor-exit v1

    .line 149
    throw p0

    .line 150
    :cond_3
    return-object v2

    .line 151
    :catchall_1
    move-exception v0

    .line 152
    move-object p0, v0

    .line 153
    monitor-exit v1

    .line 154
    throw p0
.end method

.method public final b()V
    .locals 3

    .line 1
    sget-object v0, Lv2/l;->d:Lv2/j;

    .line 2
    .line 3
    invoke-virtual {p0}, Lv2/f;->g()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-virtual {v0, v1, v2}, Lv2/j;->e(J)Lv2/j;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    iget-object p0, p0, Lv2/b;->j:Lv2/j;

    .line 12
    .line 13
    invoke-virtual {v0, p0}, Lv2/j;->c(Lv2/j;)Lv2/j;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    sput-object p0, Lv2/l;->d:Lv2/j;

    .line 18
    .line 19
    return-void
.end method

.method public c()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lv2/f;->c:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    const/4 v0, 0x1

    .line 6
    iput-boolean v0, p0, Lv2/f;->c:Z

    .line 7
    .line 8
    sget-object v0, Lv2/l;->c:Ljava/lang/Object;

    .line 9
    .line 10
    monitor-enter v0

    .line 11
    :try_start_0
    invoke-virtual {p0}, Lv2/f;->o()V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 12
    .line 13
    .line 14
    monitor-exit v0

    .line 15
    invoke-virtual {p0}, Lv2/b;->l()V

    .line 16
    .line 17
    .line 18
    return-void

    .line 19
    :catchall_0
    move-exception p0

    .line 20
    monitor-exit v0

    .line 21
    throw p0

    .line 22
    :cond_0
    return-void
.end method

.method public bridge synthetic e()Lay0/k;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lv2/b;->y()Lay0/k;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public f()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public h()I
    .locals 0

    .line 1
    iget p0, p0, Lv2/b;->g:I

    .line 2
    .line 3
    return p0
.end method

.method public i()Lay0/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lv2/b;->f:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public k()V
    .locals 1

    .line 1
    iget v0, p0, Lv2/b;->l:I

    .line 2
    .line 3
    add-int/lit8 v0, v0, 0x1

    .line 4
    .line 5
    iput v0, p0, Lv2/b;->l:I

    .line 6
    .line 7
    return-void
.end method

.method public l()V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget v1, v0, Lv2/b;->l:I

    .line 4
    .line 5
    if-lez v1, :cond_0

    .line 6
    .line 7
    goto :goto_0

    .line 8
    :cond_0
    const-string v1, "no pending nested snapshots"

    .line 9
    .line 10
    invoke-static {v1}, Ll2/q1;->a(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    :goto_0
    iget v1, v0, Lv2/b;->l:I

    .line 14
    .line 15
    add-int/lit8 v1, v1, -0x1

    .line 16
    .line 17
    iput v1, v0, Lv2/b;->l:I

    .line 18
    .line 19
    if-nez v1, :cond_8

    .line 20
    .line 21
    iget-boolean v1, v0, Lv2/b;->m:Z

    .line 22
    .line 23
    if-nez v1, :cond_8

    .line 24
    .line 25
    invoke-virtual {v0}, Lv2/b;->x()Landroidx/collection/r0;

    .line 26
    .line 27
    .line 28
    move-result-object v1

    .line 29
    if-eqz v1, :cond_7

    .line 30
    .line 31
    iget-boolean v2, v0, Lv2/b;->m:Z

    .line 32
    .line 33
    if-eqz v2, :cond_1

    .line 34
    .line 35
    const-string v2, "Unsupported operation on a snapshot that has been applied"

    .line 36
    .line 37
    invoke-static {v2}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    :cond_1
    const/4 v2, 0x0

    .line 41
    invoke-virtual {v0, v2}, Lv2/b;->B(Landroidx/collection/r0;)V

    .line 42
    .line 43
    .line 44
    invoke-virtual {v0}, Lv2/f;->g()J

    .line 45
    .line 46
    .line 47
    move-result-wide v2

    .line 48
    iget-object v4, v1, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 49
    .line 50
    iget-object v1, v1, Landroidx/collection/r0;->a:[J

    .line 51
    .line 52
    array-length v5, v1

    .line 53
    add-int/lit8 v5, v5, -0x2

    .line 54
    .line 55
    if-ltz v5, :cond_7

    .line 56
    .line 57
    const/4 v7, 0x0

    .line 58
    :goto_1
    aget-wide v8, v1, v7

    .line 59
    .line 60
    not-long v10, v8

    .line 61
    const/4 v12, 0x7

    .line 62
    shl-long/2addr v10, v12

    .line 63
    and-long/2addr v10, v8

    .line 64
    const-wide v12, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 65
    .line 66
    .line 67
    .line 68
    .line 69
    and-long/2addr v10, v12

    .line 70
    cmp-long v10, v10, v12

    .line 71
    .line 72
    if-eqz v10, :cond_6

    .line 73
    .line 74
    sub-int v10, v7, v5

    .line 75
    .line 76
    not-int v10, v10

    .line 77
    ushr-int/lit8 v10, v10, 0x1f

    .line 78
    .line 79
    const/16 v11, 0x8

    .line 80
    .line 81
    rsub-int/lit8 v10, v10, 0x8

    .line 82
    .line 83
    const/4 v12, 0x0

    .line 84
    :goto_2
    if-ge v12, v10, :cond_5

    .line 85
    .line 86
    const-wide/16 v13, 0xff

    .line 87
    .line 88
    and-long/2addr v13, v8

    .line 89
    const-wide/16 v15, 0x80

    .line 90
    .line 91
    cmp-long v13, v13, v15

    .line 92
    .line 93
    if-gez v13, :cond_4

    .line 94
    .line 95
    shl-int/lit8 v13, v7, 0x3

    .line 96
    .line 97
    add-int/2addr v13, v12

    .line 98
    aget-object v13, v4, v13

    .line 99
    .line 100
    check-cast v13, Lv2/t;

    .line 101
    .line 102
    invoke-interface {v13}, Lv2/t;->k()Lv2/v;

    .line 103
    .line 104
    .line 105
    move-result-object v13

    .line 106
    :goto_3
    if-eqz v13, :cond_4

    .line 107
    .line 108
    iget-wide v14, v13, Lv2/v;->a:J

    .line 109
    .line 110
    cmp-long v16, v14, v2

    .line 111
    .line 112
    if-eqz v16, :cond_2

    .line 113
    .line 114
    iget-object v6, v0, Lv2/b;->j:Lv2/j;

    .line 115
    .line 116
    invoke-static {v14, v15}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 117
    .line 118
    .line 119
    move-result-object v14

    .line 120
    invoke-static {v6, v14}, Lmx0/q;->A(Ljava/lang/Iterable;Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    move-result v6

    .line 124
    if-eqz v6, :cond_3

    .line 125
    .line 126
    :cond_2
    sget-object v6, Lv2/l;->a:Luu/r;

    .line 127
    .line 128
    const-wide/16 v14, 0x0

    .line 129
    .line 130
    iput-wide v14, v13, Lv2/v;->a:J

    .line 131
    .line 132
    :cond_3
    iget-object v13, v13, Lv2/v;->b:Lv2/v;

    .line 133
    .line 134
    goto :goto_3

    .line 135
    :cond_4
    shr-long/2addr v8, v11

    .line 136
    add-int/lit8 v12, v12, 0x1

    .line 137
    .line 138
    goto :goto_2

    .line 139
    :cond_5
    if-ne v10, v11, :cond_7

    .line 140
    .line 141
    :cond_6
    if-eq v7, v5, :cond_7

    .line 142
    .line 143
    add-int/lit8 v7, v7, 0x1

    .line 144
    .line 145
    goto :goto_1

    .line 146
    :cond_7
    invoke-virtual {v0}, Lv2/f;->a()V

    .line 147
    .line 148
    .line 149
    :cond_8
    return-void
.end method

.method public m()V
    .locals 1

    .line 1
    iget-boolean v0, p0, Lv2/b;->m:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-boolean v0, p0, Lv2/f;->c:Z

    .line 6
    .line 7
    if-eqz v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    invoke-virtual {p0}, Lv2/b;->v()V

    .line 11
    .line 12
    .line 13
    :cond_1
    :goto_0
    return-void
.end method

.method public n(Lv2/t;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Lv2/b;->x()Landroidx/collection/r0;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    sget-object v0, Landroidx/collection/z0;->a:Landroidx/collection/r0;

    .line 8
    .line 9
    new-instance v0, Landroidx/collection/r0;

    .line 10
    .line 11
    invoke-direct {v0}, Landroidx/collection/r0;-><init>()V

    .line 12
    .line 13
    .line 14
    invoke-virtual {p0, v0}, Lv2/b;->B(Landroidx/collection/r0;)V

    .line 15
    .line 16
    .line 17
    :cond_0
    invoke-virtual {v0, p1}, Landroidx/collection/r0;->a(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public final p()V
    .locals 3

    .line 1
    iget-object v0, p0, Lv2/b;->k:[I

    .line 2
    .line 3
    array-length v0, v0

    .line 4
    const/4 v1, 0x0

    .line 5
    :goto_0
    if-ge v1, v0, :cond_0

    .line 6
    .line 7
    iget-object v2, p0, Lv2/b;->k:[I

    .line 8
    .line 9
    aget v2, v2, v1

    .line 10
    .line 11
    invoke-static {v2}, Lv2/l;->u(I)V

    .line 12
    .line 13
    .line 14
    add-int/lit8 v1, v1, 0x1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_0
    invoke-virtual {p0}, Lv2/f;->o()V

    .line 18
    .line 19
    .line 20
    return-void
.end method

.method public t(I)V
    .locals 0

    .line 1
    iput p1, p0, Lv2/b;->g:I

    .line 2
    .line 3
    return-void
.end method

.method public u(Lay0/k;)Lv2/f;
    .locals 11

    .line 1
    iget-boolean v0, p0, Lv2/f;->c:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    const-string v0, "Cannot use a disposed snapshot"

    .line 6
    .line 7
    invoke-static {v0}, Ll2/q1;->a(Ljava/lang/String;)V

    .line 8
    .line 9
    .line 10
    :cond_0
    iget-boolean v0, p0, Lv2/b;->m:Z

    .line 11
    .line 12
    if-eqz v0, :cond_2

    .line 13
    .line 14
    iget v0, p0, Lv2/f;->d:I

    .line 15
    .line 16
    if-ltz v0, :cond_1

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_1
    const-string v0, "Unsupported operation on a disposed or applied snapshot"

    .line 20
    .line 21
    invoke-static {v0}, Ll2/q1;->b(Ljava/lang/String;)V

    .line 22
    .line 23
    .line 24
    :cond_2
    :goto_0
    invoke-virtual {p0}, Lv2/f;->g()J

    .line 25
    .line 26
    .line 27
    move-result-wide v0

    .line 28
    invoke-virtual {p0}, Lv2/f;->g()J

    .line 29
    .line 30
    .line 31
    move-result-wide v2

    .line 32
    invoke-virtual {p0, v2, v3}, Lv2/b;->A(J)V

    .line 33
    .line 34
    .line 35
    sget-object v2, Lv2/l;->c:Ljava/lang/Object;

    .line 36
    .line 37
    monitor-enter v2

    .line 38
    :try_start_0
    sget-wide v4, Lv2/l;->e:J

    .line 39
    .line 40
    const/4 v3, 0x1

    .line 41
    int-to-long v9, v3

    .line 42
    add-long v6, v4, v9

    .line 43
    .line 44
    sput-wide v6, Lv2/l;->e:J

    .line 45
    .line 46
    sget-object v6, Lv2/l;->d:Lv2/j;

    .line 47
    .line 48
    invoke-virtual {v6, v4, v5}, Lv2/j;->k(J)Lv2/j;

    .line 49
    .line 50
    .line 51
    move-result-object v6

    .line 52
    sput-object v6, Lv2/l;->d:Lv2/j;

    .line 53
    .line 54
    move v6, v3

    .line 55
    new-instance v3, Lv2/d;

    .line 56
    .line 57
    invoke-virtual {p0}, Lv2/f;->d()Lv2/j;

    .line 58
    .line 59
    .line 60
    move-result-object v7

    .line 61
    add-long/2addr v0, v9

    .line 62
    invoke-static {v7, v0, v1, v4, v5}, Lv2/l;->e(Lv2/j;JJ)Lv2/j;

    .line 63
    .line 64
    .line 65
    move-result-object v0

    .line 66
    invoke-virtual {p0}, Lv2/b;->y()Lay0/k;

    .line 67
    .line 68
    .line 69
    move-result-object v1

    .line 70
    invoke-static {p1, v1, v6}, Lv2/l;->l(Lay0/k;Lay0/k;Z)Lay0/k;

    .line 71
    .line 72
    .line 73
    move-result-object v7

    .line 74
    move-object v8, p0

    .line 75
    move-object v6, v0

    .line 76
    invoke-direct/range {v3 .. v8}, Lv2/d;-><init>(JLv2/j;Lay0/k;Lv2/f;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_1

    .line 77
    .line 78
    .line 79
    monitor-exit v2

    .line 80
    iget-boolean p0, v8, Lv2/b;->m:Z

    .line 81
    .line 82
    if-nez p0, :cond_3

    .line 83
    .line 84
    iget-boolean p0, v8, Lv2/f;->c:Z

    .line 85
    .line 86
    if-nez p0, :cond_3

    .line 87
    .line 88
    invoke-virtual {v8}, Lv2/f;->g()J

    .line 89
    .line 90
    .line 91
    move-result-wide p0

    .line 92
    monitor-enter v2

    .line 93
    :try_start_1
    sget-wide v0, Lv2/l;->e:J

    .line 94
    .line 95
    add-long v4, v0, v9

    .line 96
    .line 97
    sput-wide v4, Lv2/l;->e:J

    .line 98
    .line 99
    invoke-virtual {v8, v0, v1}, Lv2/f;->s(J)V

    .line 100
    .line 101
    .line 102
    sget-object v0, Lv2/l;->d:Lv2/j;

    .line 103
    .line 104
    invoke-virtual {v8}, Lv2/f;->g()J

    .line 105
    .line 106
    .line 107
    move-result-wide v4

    .line 108
    invoke-virtual {v0, v4, v5}, Lv2/j;->k(J)Lv2/j;

    .line 109
    .line 110
    .line 111
    move-result-object v0

    .line 112
    sput-object v0, Lv2/l;->d:Lv2/j;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 113
    .line 114
    monitor-exit v2

    .line 115
    invoke-virtual {v8}, Lv2/f;->d()Lv2/j;

    .line 116
    .line 117
    .line 118
    move-result-object v0

    .line 119
    add-long/2addr p0, v9

    .line 120
    invoke-virtual {v8}, Lv2/f;->g()J

    .line 121
    .line 122
    .line 123
    move-result-wide v1

    .line 124
    invoke-static {v0, p0, p1, v1, v2}, Lv2/l;->e(Lv2/j;JJ)Lv2/j;

    .line 125
    .line 126
    .line 127
    move-result-object p0

    .line 128
    invoke-virtual {v8, p0}, Lv2/f;->r(Lv2/j;)V

    .line 129
    .line 130
    .line 131
    return-object v3

    .line 132
    :catchall_0
    move-exception v0

    .line 133
    move-object p0, v0

    .line 134
    monitor-exit v2

    .line 135
    throw p0

    .line 136
    :cond_3
    return-object v3

    .line 137
    :catchall_1
    move-exception v0

    .line 138
    move-object p0, v0

    .line 139
    monitor-exit v2

    .line 140
    throw p0
.end method

.method public final v()V
    .locals 9

    .line 1
    invoke-virtual {p0}, Lv2/f;->g()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p0, v0, v1}, Lv2/b;->A(J)V

    .line 6
    .line 7
    .line 8
    iget-boolean v0, p0, Lv2/b;->m:Z

    .line 9
    .line 10
    if-nez v0, :cond_0

    .line 11
    .line 12
    iget-boolean v0, p0, Lv2/f;->c:Z

    .line 13
    .line 14
    if-nez v0, :cond_0

    .line 15
    .line 16
    invoke-virtual {p0}, Lv2/f;->g()J

    .line 17
    .line 18
    .line 19
    move-result-wide v0

    .line 20
    sget-object v2, Lv2/l;->c:Ljava/lang/Object;

    .line 21
    .line 22
    monitor-enter v2

    .line 23
    :try_start_0
    sget-wide v3, Lv2/l;->e:J

    .line 24
    .line 25
    const/4 v5, 0x1

    .line 26
    int-to-long v5, v5

    .line 27
    add-long v7, v3, v5

    .line 28
    .line 29
    sput-wide v7, Lv2/l;->e:J

    .line 30
    .line 31
    invoke-virtual {p0, v3, v4}, Lv2/f;->s(J)V

    .line 32
    .line 33
    .line 34
    sget-object v3, Lv2/l;->d:Lv2/j;

    .line 35
    .line 36
    invoke-virtual {p0}, Lv2/f;->g()J

    .line 37
    .line 38
    .line 39
    move-result-wide v7

    .line 40
    invoke-virtual {v3, v7, v8}, Lv2/j;->k(J)Lv2/j;

    .line 41
    .line 42
    .line 43
    move-result-object v3

    .line 44
    sput-object v3, Lv2/l;->d:Lv2/j;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 45
    .line 46
    monitor-exit v2

    .line 47
    invoke-virtual {p0}, Lv2/f;->d()Lv2/j;

    .line 48
    .line 49
    .line 50
    move-result-object v2

    .line 51
    add-long/2addr v0, v5

    .line 52
    invoke-virtual {p0}, Lv2/f;->g()J

    .line 53
    .line 54
    .line 55
    move-result-wide v3

    .line 56
    invoke-static {v2, v0, v1, v3, v4}, Lv2/l;->e(Lv2/j;JJ)Lv2/j;

    .line 57
    .line 58
    .line 59
    move-result-object v0

    .line 60
    invoke-virtual {p0, v0}, Lv2/f;->r(Lv2/j;)V

    .line 61
    .line 62
    .line 63
    return-void

    .line 64
    :catchall_0
    move-exception p0

    .line 65
    monitor-exit v2

    .line 66
    throw p0

    .line 67
    :cond_0
    return-void
.end method

.method public w()Lv2/p;
    .locals 22

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual {v0}, Lv2/b;->x()Landroidx/collection/r0;

    .line 4
    .line 5
    .line 6
    move-result-object v3

    .line 7
    const/4 v6, 0x0

    .line 8
    if-eqz v3, :cond_0

    .line 9
    .line 10
    sget-object v1, Lv2/l;->j:Lv2/a;

    .line 11
    .line 12
    iget-wide v1, v1, Lv2/f;->b:J

    .line 13
    .line 14
    sget-object v4, Lv2/l;->d:Lv2/j;

    .line 15
    .line 16
    invoke-virtual {v4, v1, v2}, Lv2/j;->e(J)Lv2/j;

    .line 17
    .line 18
    .line 19
    move-result-object v4

    .line 20
    invoke-static {v1, v2, v0, v4}, Lv2/l;->c(JLv2/b;Lv2/j;)Ljava/util/HashMap;

    .line 21
    .line 22
    .line 23
    move-result-object v1

    .line 24
    move-object v4, v1

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    move-object v4, v6

    .line 27
    :goto_0
    sget-object v1, Lmx0/s;->d:Lmx0/s;

    .line 28
    .line 29
    sget-object v7, Lv2/l;->c:Ljava/lang/Object;

    .line 30
    .line 31
    monitor-enter v7

    .line 32
    :try_start_0
    invoke-static {v0}, Lv2/l;->d(Lv2/f;)V

    .line 33
    .line 34
    .line 35
    if-eqz v3, :cond_3

    .line 36
    .line 37
    iget v2, v3, Landroidx/collection/r0;->d:I

    .line 38
    .line 39
    if-nez v2, :cond_1

    .line 40
    .line 41
    goto :goto_1

    .line 42
    :cond_1
    sget-object v8, Lv2/l;->j:Lv2/a;

    .line 43
    .line 44
    sget-wide v1, Lv2/l;->e:J

    .line 45
    .line 46
    sget-object v5, Lv2/l;->d:Lv2/j;

    .line 47
    .line 48
    iget-wide v9, v8, Lv2/f;->b:J

    .line 49
    .line 50
    invoke-virtual {v5, v9, v10}, Lv2/j;->e(J)Lv2/j;

    .line 51
    .line 52
    .line 53
    move-result-object v5

    .line 54
    invoke-virtual/range {v0 .. v5}, Lv2/b;->z(JLandroidx/collection/r0;Ljava/util/HashMap;Lv2/j;)Lv2/p;

    .line 55
    .line 56
    .line 57
    move-result-object v1

    .line 58
    sget-object v2, Lv2/h;->b:Lv2/h;

    .line 59
    .line 60
    invoke-virtual {v1, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 61
    .line 62
    .line 63
    move-result v2
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 64
    if-nez v2, :cond_2

    .line 65
    .line 66
    monitor-exit v7

    .line 67
    return-object v1

    .line 68
    :cond_2
    :try_start_1
    invoke-virtual {v0}, Lv2/b;->b()V

    .line 69
    .line 70
    .line 71
    iget-object v1, v8, Lv2/b;->h:Landroidx/collection/r0;

    .line 72
    .line 73
    sget-object v2, Lv2/l;->a:Luu/r;

    .line 74
    .line 75
    invoke-static {v8, v2}, Lv2/l;->v(Lv2/a;Lay0/k;)Ljava/lang/Object;

    .line 76
    .line 77
    .line 78
    invoke-virtual {v0, v6}, Lv2/b;->B(Landroidx/collection/r0;)V

    .line 79
    .line 80
    .line 81
    iput-object v6, v8, Lv2/b;->h:Landroidx/collection/r0;

    .line 82
    .line 83
    sget-object v2, Lv2/l;->h:Ljava/lang/Object;

    .line 84
    .line 85
    goto :goto_2

    .line 86
    :catchall_0
    move-exception v0

    .line 87
    goto/16 :goto_c

    .line 88
    .line 89
    :cond_3
    :goto_1
    invoke-virtual {v0}, Lv2/b;->b()V

    .line 90
    .line 91
    .line 92
    sget-object v2, Lv2/l;->j:Lv2/a;

    .line 93
    .line 94
    iget-object v4, v2, Lv2/b;->h:Landroidx/collection/r0;

    .line 95
    .line 96
    sget-object v5, Lv2/l;->a:Luu/r;

    .line 97
    .line 98
    invoke-static {v2, v5}, Lv2/l;->v(Lv2/a;Lay0/k;)Ljava/lang/Object;

    .line 99
    .line 100
    .line 101
    if-eqz v4, :cond_4

    .line 102
    .line 103
    invoke-virtual {v4}, Landroidx/collection/r0;->h()Z

    .line 104
    .line 105
    .line 106
    move-result v2

    .line 107
    if-eqz v2, :cond_4

    .line 108
    .line 109
    sget-object v1, Lv2/l;->h:Ljava/lang/Object;
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 110
    .line 111
    move-object v2, v1

    .line 112
    move-object v1, v4

    .line 113
    goto :goto_2

    .line 114
    :cond_4
    move-object v2, v1

    .line 115
    move-object v1, v6

    .line 116
    :goto_2
    monitor-exit v7

    .line 117
    const/4 v4, 0x1

    .line 118
    iput-boolean v4, v0, Lv2/b;->m:Z

    .line 119
    .line 120
    if-eqz v1, :cond_5

    .line 121
    .line 122
    new-instance v5, Ln2/d;

    .line 123
    .line 124
    invoke-direct {v5, v1}, Ln2/d;-><init>(Landroidx/collection/r0;)V

    .line 125
    .line 126
    .line 127
    invoke-virtual {v1}, Landroidx/collection/r0;->g()Z

    .line 128
    .line 129
    .line 130
    move-result v7

    .line 131
    if-nez v7, :cond_5

    .line 132
    .line 133
    move-object v7, v2

    .line 134
    check-cast v7, Ljava/util/Collection;

    .line 135
    .line 136
    invoke-interface {v7}, Ljava/util/Collection;->size()I

    .line 137
    .line 138
    .line 139
    move-result v7

    .line 140
    const/4 v8, 0x0

    .line 141
    :goto_3
    if-ge v8, v7, :cond_5

    .line 142
    .line 143
    invoke-interface {v2, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 144
    .line 145
    .line 146
    move-result-object v9

    .line 147
    check-cast v9, Lay0/n;

    .line 148
    .line 149
    invoke-interface {v9, v5, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    add-int/lit8 v8, v8, 0x1

    .line 153
    .line 154
    goto :goto_3

    .line 155
    :cond_5
    if-eqz v3, :cond_6

    .line 156
    .line 157
    invoke-virtual {v3}, Landroidx/collection/r0;->h()Z

    .line 158
    .line 159
    .line 160
    move-result v5

    .line 161
    if-eqz v5, :cond_6

    .line 162
    .line 163
    new-instance v5, Ln2/d;

    .line 164
    .line 165
    invoke-direct {v5, v3}, Ln2/d;-><init>(Landroidx/collection/r0;)V

    .line 166
    .line 167
    .line 168
    move-object v7, v2

    .line 169
    check-cast v7, Ljava/util/Collection;

    .line 170
    .line 171
    invoke-interface {v7}, Ljava/util/Collection;->size()I

    .line 172
    .line 173
    .line 174
    move-result v7

    .line 175
    const/4 v8, 0x0

    .line 176
    :goto_4
    if-ge v8, v7, :cond_6

    .line 177
    .line 178
    invoke-interface {v2, v8}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 179
    .line 180
    .line 181
    move-result-object v9

    .line 182
    check-cast v9, Lay0/n;

    .line 183
    .line 184
    invoke-interface {v9, v5, v0}, Lay0/n;->invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 185
    .line 186
    .line 187
    add-int/lit8 v8, v8, 0x1

    .line 188
    .line 189
    goto :goto_4

    .line 190
    :cond_6
    sget-object v2, Lv2/l;->c:Ljava/lang/Object;

    .line 191
    .line 192
    monitor-enter v2

    .line 193
    :try_start_2
    invoke-virtual {v0}, Lv2/b;->p()V

    .line 194
    .line 195
    .line 196
    invoke-static {}, Lv2/l;->g()V

    .line 197
    .line 198
    .line 199
    const/4 v5, 0x7

    .line 200
    const-wide v11, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 201
    .line 202
    .line 203
    .line 204
    .line 205
    const/16 v13, 0x8

    .line 206
    .line 207
    if-eqz v1, :cond_a

    .line 208
    .line 209
    iget-object v14, v1, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 210
    .line 211
    iget-object v1, v1, Landroidx/collection/r0;->a:[J

    .line 212
    .line 213
    array-length v15, v1

    .line 214
    add-int/lit8 v15, v15, -0x2

    .line 215
    .line 216
    if-ltz v15, :cond_a

    .line 217
    .line 218
    const/4 v4, 0x0

    .line 219
    const-wide/16 v16, 0x80

    .line 220
    .line 221
    :goto_5
    aget-wide v7, v1, v4

    .line 222
    .line 223
    const-wide/16 v18, 0xff

    .line 224
    .line 225
    not-long v9, v7

    .line 226
    shl-long/2addr v9, v5

    .line 227
    and-long/2addr v9, v7

    .line 228
    and-long/2addr v9, v11

    .line 229
    cmp-long v9, v9, v11

    .line 230
    .line 231
    if-eqz v9, :cond_9

    .line 232
    .line 233
    sub-int v9, v4, v15

    .line 234
    .line 235
    not-int v9, v9

    .line 236
    ushr-int/lit8 v9, v9, 0x1f

    .line 237
    .line 238
    rsub-int/lit8 v9, v9, 0x8

    .line 239
    .line 240
    const/4 v10, 0x0

    .line 241
    :goto_6
    if-ge v10, v9, :cond_8

    .line 242
    .line 243
    and-long v20, v7, v18

    .line 244
    .line 245
    cmp-long v20, v20, v16

    .line 246
    .line 247
    if-gez v20, :cond_7

    .line 248
    .line 249
    shl-int/lit8 v20, v4, 0x3

    .line 250
    .line 251
    add-int v20, v20, v10

    .line 252
    .line 253
    aget-object v20, v14, v20

    .line 254
    .line 255
    check-cast v20, Lv2/t;

    .line 256
    .line 257
    invoke-static/range {v20 .. v20}, Lv2/l;->q(Lv2/t;)V

    .line 258
    .line 259
    .line 260
    goto :goto_7

    .line 261
    :catchall_1
    move-exception v0

    .line 262
    goto :goto_b

    .line 263
    :cond_7
    :goto_7
    shr-long/2addr v7, v13

    .line 264
    add-int/lit8 v10, v10, 0x1

    .line 265
    .line 266
    goto :goto_6

    .line 267
    :cond_8
    if-ne v9, v13, :cond_b

    .line 268
    .line 269
    :cond_9
    if-eq v4, v15, :cond_b

    .line 270
    .line 271
    add-int/lit8 v4, v4, 0x1

    .line 272
    .line 273
    goto :goto_5

    .line 274
    :cond_a
    const-wide/16 v16, 0x80

    .line 275
    .line 276
    const-wide/16 v18, 0xff

    .line 277
    .line 278
    :cond_b
    if-eqz v3, :cond_f

    .line 279
    .line 280
    iget-object v1, v3, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 281
    .line 282
    iget-object v3, v3, Landroidx/collection/r0;->a:[J

    .line 283
    .line 284
    array-length v4, v3

    .line 285
    add-int/lit8 v4, v4, -0x2

    .line 286
    .line 287
    if-ltz v4, :cond_f

    .line 288
    .line 289
    const/4 v7, 0x0

    .line 290
    :goto_8
    aget-wide v8, v3, v7

    .line 291
    .line 292
    not-long v14, v8

    .line 293
    shl-long/2addr v14, v5

    .line 294
    and-long/2addr v14, v8

    .line 295
    and-long/2addr v14, v11

    .line 296
    cmp-long v10, v14, v11

    .line 297
    .line 298
    if-eqz v10, :cond_e

    .line 299
    .line 300
    sub-int v10, v7, v4

    .line 301
    .line 302
    not-int v10, v10

    .line 303
    ushr-int/lit8 v10, v10, 0x1f

    .line 304
    .line 305
    rsub-int/lit8 v10, v10, 0x8

    .line 306
    .line 307
    const/4 v14, 0x0

    .line 308
    :goto_9
    if-ge v14, v10, :cond_d

    .line 309
    .line 310
    and-long v20, v8, v18

    .line 311
    .line 312
    cmp-long v15, v20, v16

    .line 313
    .line 314
    if-gez v15, :cond_c

    .line 315
    .line 316
    shl-int/lit8 v15, v7, 0x3

    .line 317
    .line 318
    add-int/2addr v15, v14

    .line 319
    aget-object v15, v1, v15

    .line 320
    .line 321
    check-cast v15, Lv2/t;

    .line 322
    .line 323
    invoke-static {v15}, Lv2/l;->q(Lv2/t;)V

    .line 324
    .line 325
    .line 326
    :cond_c
    shr-long/2addr v8, v13

    .line 327
    add-int/lit8 v14, v14, 0x1

    .line 328
    .line 329
    goto :goto_9

    .line 330
    :cond_d
    if-ne v10, v13, :cond_f

    .line 331
    .line 332
    :cond_e
    if-eq v7, v4, :cond_f

    .line 333
    .line 334
    add-int/lit8 v7, v7, 0x1

    .line 335
    .line 336
    goto :goto_8

    .line 337
    :cond_f
    iget-object v1, v0, Lv2/b;->i:Ljava/util/ArrayList;

    .line 338
    .line 339
    if-eqz v1, :cond_10

    .line 340
    .line 341
    invoke-interface {v1}, Ljava/util/Collection;->size()I

    .line 342
    .line 343
    .line 344
    move-result v3

    .line 345
    const/4 v4, 0x0

    .line 346
    :goto_a
    if-ge v4, v3, :cond_10

    .line 347
    .line 348
    invoke-interface {v1, v4}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 349
    .line 350
    .line 351
    move-result-object v5

    .line 352
    check-cast v5, Lv2/t;

    .line 353
    .line 354
    invoke-static {v5}, Lv2/l;->q(Lv2/t;)V

    .line 355
    .line 356
    .line 357
    add-int/lit8 v4, v4, 0x1

    .line 358
    .line 359
    goto :goto_a

    .line 360
    :cond_10
    iput-object v6, v0, Lv2/b;->i:Ljava/util/ArrayList;
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_1

    .line 361
    .line 362
    monitor-exit v2

    .line 363
    sget-object v0, Lv2/h;->b:Lv2/h;

    .line 364
    .line 365
    return-object v0

    .line 366
    :goto_b
    monitor-exit v2

    .line 367
    throw v0

    .line 368
    :goto_c
    monitor-exit v7

    .line 369
    throw v0
.end method

.method public x()Landroidx/collection/r0;
    .locals 0

    .line 1
    iget-object p0, p0, Lv2/b;->h:Landroidx/collection/r0;

    .line 2
    .line 3
    return-object p0
.end method

.method public y()Lay0/k;
    .locals 0

    .line 1
    iget-object p0, p0, Lv2/b;->e:Lay0/k;

    .line 2
    .line 3
    return-object p0
.end method

.method public final z(JLandroidx/collection/r0;Ljava/util/HashMap;Lv2/j;)Lv2/p;
    .locals 28

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-wide/from16 v1, p1

    .line 4
    .line 5
    move-object/from16 v3, p3

    .line 6
    .line 7
    move-object/from16 v4, p4

    .line 8
    .line 9
    invoke-virtual {v0}, Lv2/f;->d()Lv2/j;

    .line 10
    .line 11
    .line 12
    move-result-object v5

    .line 13
    invoke-virtual {v0}, Lv2/f;->g()J

    .line 14
    .line 15
    .line 16
    move-result-wide v6

    .line 17
    invoke-virtual {v5, v6, v7}, Lv2/j;->k(J)Lv2/j;

    .line 18
    .line 19
    .line 20
    move-result-object v5

    .line 21
    iget-object v6, v0, Lv2/b;->j:Lv2/j;

    .line 22
    .line 23
    invoke-virtual {v5, v6}, Lv2/j;->i(Lv2/j;)Lv2/j;

    .line 24
    .line 25
    .line 26
    move-result-object v5

    .line 27
    iget-object v6, v3, Landroidx/collection/r0;->b:[Ljava/lang/Object;

    .line 28
    .line 29
    iget-object v7, v3, Landroidx/collection/r0;->a:[J

    .line 30
    .line 31
    array-length v8, v7

    .line 32
    add-int/lit8 v8, v8, -0x2

    .line 33
    .line 34
    if-ltz v8, :cond_11

    .line 35
    .line 36
    const/4 v11, 0x0

    .line 37
    const/4 v12, 0x0

    .line 38
    const/4 v13, 0x0

    .line 39
    :goto_0
    aget-wide v14, v7, v11

    .line 40
    .line 41
    const/16 v16, 0x0

    .line 42
    .line 43
    not-long v9, v14

    .line 44
    const/16 v17, 0x7

    .line 45
    .line 46
    shl-long v9, v9, v17

    .line 47
    .line 48
    and-long/2addr v9, v14

    .line 49
    const-wide v17, -0x7f7f7f7f7f7f7f80L    # -2.937446524422997E-306

    .line 50
    .line 51
    .line 52
    .line 53
    .line 54
    and-long v9, v9, v17

    .line 55
    .line 56
    cmp-long v9, v9, v17

    .line 57
    .line 58
    if-eqz v9, :cond_f

    .line 59
    .line 60
    sub-int v9, v11, v8

    .line 61
    .line 62
    not-int v9, v9

    .line 63
    ushr-int/lit8 v9, v9, 0x1f

    .line 64
    .line 65
    const/16 v10, 0x8

    .line 66
    .line 67
    rsub-int/lit8 v9, v9, 0x8

    .line 68
    .line 69
    move/from16 v17, v10

    .line 70
    .line 71
    const/4 v10, 0x0

    .line 72
    :goto_1
    if-ge v10, v9, :cond_e

    .line 73
    .line 74
    const-wide/16 v18, 0xff

    .line 75
    .line 76
    and-long v18, v14, v18

    .line 77
    .line 78
    const-wide/16 v20, 0x80

    .line 79
    .line 80
    cmp-long v18, v18, v20

    .line 81
    .line 82
    if-gez v18, :cond_d

    .line 83
    .line 84
    shl-int/lit8 v18, v11, 0x3

    .line 85
    .line 86
    add-int v18, v18, v10

    .line 87
    .line 88
    aget-object v18, v6, v18

    .line 89
    .line 90
    move-object/from16 v19, v6

    .line 91
    .line 92
    move-object/from16 v6, v18

    .line 93
    .line 94
    check-cast v6, Lv2/t;

    .line 95
    .line 96
    move-object/from16 v18, v7

    .line 97
    .line 98
    invoke-interface {v6}, Lv2/t;->k()Lv2/v;

    .line 99
    .line 100
    .line 101
    move-result-object v7

    .line 102
    move/from16 v20, v10

    .line 103
    .line 104
    move-object/from16 v21, v12

    .line 105
    .line 106
    move-object/from16 v10, p5

    .line 107
    .line 108
    invoke-static {v7, v1, v2, v10}, Lv2/l;->s(Lv2/v;JLv2/j;)Lv2/v;

    .line 109
    .line 110
    .line 111
    move-result-object v12

    .line 112
    if-nez v12, :cond_0

    .line 113
    .line 114
    move-object/from16 v25, v5

    .line 115
    .line 116
    move-object/from16 v22, v13

    .line 117
    .line 118
    move-wide/from16 v23, v14

    .line 119
    .line 120
    goto :goto_2

    .line 121
    :cond_0
    move-object/from16 v22, v13

    .line 122
    .line 123
    move-wide/from16 v23, v14

    .line 124
    .line 125
    invoke-virtual {v0}, Lv2/f;->g()J

    .line 126
    .line 127
    .line 128
    move-result-wide v13

    .line 129
    invoke-static {v7, v13, v14, v5}, Lv2/l;->s(Lv2/v;JLv2/j;)Lv2/v;

    .line 130
    .line 131
    .line 132
    move-result-object v13

    .line 133
    if-nez v13, :cond_1

    .line 134
    .line 135
    move-object/from16 v25, v5

    .line 136
    .line 137
    goto :goto_2

    .line 138
    :cond_1
    iget-wide v14, v13, Lv2/v;->a:J

    .line 139
    .line 140
    move-object/from16 v25, v5

    .line 141
    .line 142
    const/4 v5, 0x1

    .line 143
    move-wide/from16 v26, v14

    .line 144
    .line 145
    int-to-long v14, v5

    .line 146
    cmp-long v5, v26, v14

    .line 147
    .line 148
    if-nez v5, :cond_2

    .line 149
    .line 150
    :goto_2
    goto/16 :goto_8

    .line 151
    .line 152
    :cond_2
    invoke-virtual {v12, v13}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 153
    .line 154
    .line 155
    move-result v5

    .line 156
    if-nez v5, :cond_c

    .line 157
    .line 158
    invoke-virtual {v0}, Lv2/f;->g()J

    .line 159
    .line 160
    .line 161
    move-result-wide v14

    .line 162
    invoke-virtual {v0}, Lv2/f;->d()Lv2/j;

    .line 163
    .line 164
    .line 165
    move-result-object v5

    .line 166
    invoke-static {v7, v14, v15, v5}, Lv2/l;->s(Lv2/v;JLv2/j;)Lv2/v;

    .line 167
    .line 168
    .line 169
    move-result-object v5

    .line 170
    if-eqz v5, :cond_b

    .line 171
    .line 172
    if-eqz v4, :cond_3

    .line 173
    .line 174
    invoke-interface {v4, v12}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 175
    .line 176
    .line 177
    move-result-object v7

    .line 178
    check-cast v7, Lv2/v;

    .line 179
    .line 180
    if-nez v7, :cond_4

    .line 181
    .line 182
    :cond_3
    invoke-interface {v6, v13, v12, v5}, Lv2/t;->m(Lv2/v;Lv2/v;Lv2/v;)Lv2/v;

    .line 183
    .line 184
    .line 185
    move-result-object v7

    .line 186
    :cond_4
    if-nez v7, :cond_5

    .line 187
    .line 188
    new-instance v1, Lv2/g;

    .line 189
    .line 190
    invoke-direct {v1, v0}, Lv2/g;-><init>(Lv2/b;)V

    .line 191
    .line 192
    .line 193
    return-object v1

    .line 194
    :cond_5
    invoke-virtual {v7, v5}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 195
    .line 196
    .line 197
    move-result v5

    .line 198
    if-nez v5, :cond_c

    .line 199
    .line 200
    invoke-virtual {v7, v12}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 201
    .line 202
    .line 203
    move-result v5

    .line 204
    if-eqz v5, :cond_8

    .line 205
    .line 206
    if-nez v21, :cond_6

    .line 207
    .line 208
    new-instance v5, Ljava/util/ArrayList;

    .line 209
    .line 210
    invoke-direct {v5}, Ljava/util/ArrayList;-><init>()V

    .line 211
    .line 212
    .line 213
    goto :goto_3

    .line 214
    :cond_6
    move-object/from16 v5, v21

    .line 215
    .line 216
    :goto_3
    invoke-virtual {v0}, Lv2/f;->g()J

    .line 217
    .line 218
    .line 219
    move-result-wide v13

    .line 220
    invoke-virtual {v12, v13, v14}, Lv2/v;->b(J)Lv2/v;

    .line 221
    .line 222
    .line 223
    move-result-object v7

    .line 224
    new-instance v12, Llx0/l;

    .line 225
    .line 226
    invoke-direct {v12, v6, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 227
    .line 228
    .line 229
    invoke-interface {v5, v12}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 230
    .line 231
    .line 232
    if-nez v22, :cond_7

    .line 233
    .line 234
    new-instance v13, Ljava/util/ArrayList;

    .line 235
    .line 236
    invoke-direct {v13}, Ljava/util/ArrayList;-><init>()V

    .line 237
    .line 238
    .line 239
    goto :goto_4

    .line 240
    :cond_7
    move-object/from16 v13, v22

    .line 241
    .line 242
    :goto_4
    invoke-interface {v13, v6}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 243
    .line 244
    .line 245
    move-object v12, v5

    .line 246
    goto :goto_9

    .line 247
    :cond_8
    if-nez v21, :cond_9

    .line 248
    .line 249
    new-instance v12, Ljava/util/ArrayList;

    .line 250
    .line 251
    invoke-direct {v12}, Ljava/util/ArrayList;-><init>()V

    .line 252
    .line 253
    .line 254
    goto :goto_5

    .line 255
    :cond_9
    move-object/from16 v12, v21

    .line 256
    .line 257
    :goto_5
    invoke-virtual {v7, v13}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 258
    .line 259
    .line 260
    move-result v5

    .line 261
    if-nez v5, :cond_a

    .line 262
    .line 263
    new-instance v5, Llx0/l;

    .line 264
    .line 265
    invoke-direct {v5, v6, v7}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 266
    .line 267
    .line 268
    goto :goto_6

    .line 269
    :cond_a
    invoke-virtual {v0}, Lv2/f;->g()J

    .line 270
    .line 271
    .line 272
    move-result-wide v14

    .line 273
    invoke-virtual {v13, v14, v15}, Lv2/v;->b(J)Lv2/v;

    .line 274
    .line 275
    .line 276
    move-result-object v5

    .line 277
    new-instance v7, Llx0/l;

    .line 278
    .line 279
    invoke-direct {v7, v6, v5}, Llx0/l;-><init>(Ljava/lang/Object;Ljava/lang/Object;)V

    .line 280
    .line 281
    .line 282
    move-object v5, v7

    .line 283
    :goto_6
    invoke-interface {v12, v5}, Ljava/util/List;->add(Ljava/lang/Object;)Z

    .line 284
    .line 285
    .line 286
    :goto_7
    move-object/from16 v13, v22

    .line 287
    .line 288
    goto :goto_9

    .line 289
    :cond_b
    invoke-static {}, Lv2/l;->r()V

    .line 290
    .line 291
    .line 292
    throw v16

    .line 293
    :cond_c
    :goto_8
    move-object/from16 v12, v21

    .line 294
    .line 295
    goto :goto_7

    .line 296
    :cond_d
    move-object/from16 v25, v5

    .line 297
    .line 298
    move-object/from16 v19, v6

    .line 299
    .line 300
    move-object/from16 v18, v7

    .line 301
    .line 302
    move/from16 v20, v10

    .line 303
    .line 304
    move-object/from16 v21, v12

    .line 305
    .line 306
    move-object/from16 v22, v13

    .line 307
    .line 308
    move-wide/from16 v23, v14

    .line 309
    .line 310
    move-object/from16 v10, p5

    .line 311
    .line 312
    :goto_9
    shr-long v14, v23, v17

    .line 313
    .line 314
    add-int/lit8 v5, v20, 0x1

    .line 315
    .line 316
    move v10, v5

    .line 317
    move-object/from16 v7, v18

    .line 318
    .line 319
    move-object/from16 v6, v19

    .line 320
    .line 321
    move-object/from16 v5, v25

    .line 322
    .line 323
    goto/16 :goto_1

    .line 324
    .line 325
    :cond_e
    move-object/from16 v10, p5

    .line 326
    .line 327
    move-object/from16 v25, v5

    .line 328
    .line 329
    move-object/from16 v19, v6

    .line 330
    .line 331
    move-object/from16 v18, v7

    .line 332
    .line 333
    move-object/from16 v21, v12

    .line 334
    .line 335
    move-object/from16 v22, v13

    .line 336
    .line 337
    move/from16 v5, v17

    .line 338
    .line 339
    if-ne v9, v5, :cond_12

    .line 340
    .line 341
    goto :goto_a

    .line 342
    :cond_f
    move-object/from16 v10, p5

    .line 343
    .line 344
    move-object/from16 v25, v5

    .line 345
    .line 346
    move-object/from16 v19, v6

    .line 347
    .line 348
    move-object/from16 v18, v7

    .line 349
    .line 350
    :goto_a
    if-eq v11, v8, :cond_10

    .line 351
    .line 352
    add-int/lit8 v11, v11, 0x1

    .line 353
    .line 354
    move-object/from16 v7, v18

    .line 355
    .line 356
    move-object/from16 v6, v19

    .line 357
    .line 358
    move-object/from16 v5, v25

    .line 359
    .line 360
    goto/16 :goto_0

    .line 361
    .line 362
    :cond_10
    move-object v9, v12

    .line 363
    goto :goto_b

    .line 364
    :cond_11
    const/16 v16, 0x0

    .line 365
    .line 366
    move-object/from16 v9, v16

    .line 367
    .line 368
    move-object v13, v9

    .line 369
    :goto_b
    move-object v12, v9

    .line 370
    :cond_12
    if-eqz v12, :cond_13

    .line 371
    .line 372
    invoke-virtual {v0}, Lv2/b;->v()V

    .line 373
    .line 374
    .line 375
    invoke-interface {v12}, Ljava/util/Collection;->size()I

    .line 376
    .line 377
    .line 378
    move-result v4

    .line 379
    const/4 v5, 0x0

    .line 380
    :goto_c
    if-ge v5, v4, :cond_13

    .line 381
    .line 382
    invoke-interface {v12, v5}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 383
    .line 384
    .line 385
    move-result-object v6

    .line 386
    check-cast v6, Llx0/l;

    .line 387
    .line 388
    iget-object v7, v6, Llx0/l;->d:Ljava/lang/Object;

    .line 389
    .line 390
    check-cast v7, Lv2/t;

    .line 391
    .line 392
    iget-object v6, v6, Llx0/l;->e:Ljava/lang/Object;

    .line 393
    .line 394
    check-cast v6, Lv2/v;

    .line 395
    .line 396
    iput-wide v1, v6, Lv2/v;->a:J

    .line 397
    .line 398
    sget-object v8, Lv2/l;->c:Ljava/lang/Object;

    .line 399
    .line 400
    monitor-enter v8

    .line 401
    :try_start_0
    invoke-interface {v7}, Lv2/t;->k()Lv2/v;

    .line 402
    .line 403
    .line 404
    move-result-object v9

    .line 405
    iput-object v9, v6, Lv2/v;->b:Lv2/v;

    .line 406
    .line 407
    invoke-interface {v7, v6}, Lv2/t;->n(Lv2/v;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 408
    .line 409
    .line 410
    monitor-exit v8

    .line 411
    add-int/lit8 v5, v5, 0x1

    .line 412
    .line 413
    goto :goto_c

    .line 414
    :catchall_0
    move-exception v0

    .line 415
    monitor-exit v8

    .line 416
    throw v0

    .line 417
    :cond_13
    if-eqz v13, :cond_16

    .line 418
    .line 419
    invoke-interface {v13}, Ljava/util/Collection;->size()I

    .line 420
    .line 421
    .line 422
    move-result v1

    .line 423
    const/4 v10, 0x0

    .line 424
    :goto_d
    if-ge v10, v1, :cond_14

    .line 425
    .line 426
    invoke-interface {v13, v10}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 427
    .line 428
    .line 429
    move-result-object v2

    .line 430
    check-cast v2, Lv2/t;

    .line 431
    .line 432
    invoke-virtual {v3, v2}, Landroidx/collection/r0;->l(Ljava/lang/Object;)Z

    .line 433
    .line 434
    .line 435
    add-int/lit8 v10, v10, 0x1

    .line 436
    .line 437
    goto :goto_d

    .line 438
    :cond_14
    iget-object v1, v0, Lv2/b;->i:Ljava/util/ArrayList;

    .line 439
    .line 440
    if-nez v1, :cond_15

    .line 441
    .line 442
    goto :goto_e

    .line 443
    :cond_15
    invoke-static {v13, v1}, Lmx0/q;->a0(Ljava/lang/Iterable;Ljava/util/Collection;)Ljava/util/ArrayList;

    .line 444
    .line 445
    .line 446
    move-result-object v13

    .line 447
    :goto_e
    iput-object v13, v0, Lv2/b;->i:Ljava/util/ArrayList;

    .line 448
    .line 449
    :cond_16
    sget-object v0, Lv2/h;->b:Lv2/h;

    .line 450
    .line 451
    return-object v0
.end method
