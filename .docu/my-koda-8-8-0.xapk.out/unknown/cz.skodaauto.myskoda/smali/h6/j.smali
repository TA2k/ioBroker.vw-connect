.class public final Lh6/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/s;


# instance fields
.field public d:J

.field public e:Ljava/lang/Object;

.field public f:Ljava/lang/Object;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    sget-object v0, Lq3/c;->d:Lq3/c;

    .line 3
    new-instance v0, Lq3/d;

    invoke-direct {v0}, Lq3/d;-><init>()V

    iput-object v0, p0, Lh6/j;->e:Ljava/lang/Object;

    .line 4
    new-instance v0, Lq3/d;

    invoke-direct {v0}, Lq3/d;-><init>()V

    iput-object v0, p0, Lh6/j;->f:Ljava/lang/Object;

    return-void
.end method

.method public constructor <init>(Lh0/s;Lh0/j2;J)V
    .locals 0

    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    iput-object p1, p0, Lh6/j;->e:Ljava/lang/Object;

    .line 7
    iput-object p2, p0, Lh6/j;->f:Ljava/lang/Object;

    .line 8
    iput-wide p3, p0, Lh6/j;->d:J

    return-void
.end method


# virtual methods
.method public a()I
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh0/s;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-interface {p0}, Lh0/s;->a()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    return p0

    .line 12
    :cond_0
    const/4 p0, 0x1

    .line 13
    return p0
.end method

.method public b()Lh0/j2;
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/j;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh0/j2;

    .line 4
    .line 5
    return-object p0
.end method

.method public c()J
    .locals 4

    .line 1
    iget-object v0, p0, Lh6/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lh0/s;

    .line 4
    .line 5
    if-eqz v0, :cond_0

    .line 6
    .line 7
    invoke-interface {v0}, Lh0/s;->c()J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    return-wide v0

    .line 12
    :cond_0
    iget-wide v0, p0, Lh6/j;->d:J

    .line 13
    .line 14
    const-wide/16 v2, -0x1

    .line 15
    .line 16
    cmp-long p0, v0, v2

    .line 17
    .line 18
    if-eqz p0, :cond_1

    .line 19
    .line 20
    return-wide v0

    .line 21
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 22
    .line 23
    const-string v0, "No timestamp is available."

    .line 24
    .line 25
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    throw p0
.end method

.method public d(JJ)V
    .locals 3

    .line 1
    iget-object v0, p0, Lh6/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lq3/d;

    .line 4
    .line 5
    const/16 v1, 0x20

    .line 6
    .line 7
    shr-long v1, p3, v1

    .line 8
    .line 9
    long-to-int v1, v1

    .line 10
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    invoke-virtual {v0, p1, p2, v1}, Lq3/d;->a(JF)V

    .line 15
    .line 16
    .line 17
    iget-object p0, p0, Lh6/j;->f:Ljava/lang/Object;

    .line 18
    .line 19
    check-cast p0, Lq3/d;

    .line 20
    .line 21
    const-wide v0, 0xffffffffL

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    and-long/2addr p3, v0

    .line 27
    long-to-int p3, p3

    .line 28
    invoke-static {p3}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 29
    .line 30
    .line 31
    move-result p3

    .line 32
    invoke-virtual {p0, p1, p2, p3}, Lq3/d;->a(JF)V

    .line 33
    .line 34
    .line 35
    return-void
.end method

.method public e(J)J
    .locals 2

    .line 1
    invoke-static {p1, p2}, Lt4/q;->b(J)F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    const/4 v1, 0x0

    .line 6
    cmpl-float v0, v0, v1

    .line 7
    .line 8
    if-lez v0, :cond_0

    .line 9
    .line 10
    invoke-static {p1, p2}, Lt4/q;->c(J)F

    .line 11
    .line 12
    .line 13
    move-result v0

    .line 14
    cmpl-float v0, v0, v1

    .line 15
    .line 16
    if-lez v0, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 20
    .line 21
    const-string v1, "maximumVelocity should be a positive value. You specified="

    .line 22
    .line 23
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 24
    .line 25
    .line 26
    invoke-static {p1, p2}, Lt4/q;->g(J)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object v0

    .line 37
    invoke-static {v0}, Ls3/a;->b(Ljava/lang/String;)V

    .line 38
    .line 39
    .line 40
    :goto_0
    iget-object v0, p0, Lh6/j;->e:Ljava/lang/Object;

    .line 41
    .line 42
    check-cast v0, Lq3/d;

    .line 43
    .line 44
    invoke-static {p1, p2}, Lt4/q;->b(J)F

    .line 45
    .line 46
    .line 47
    move-result v1

    .line 48
    invoke-virtual {v0, v1}, Lq3/d;->b(F)F

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    iget-object p0, p0, Lh6/j;->f:Ljava/lang/Object;

    .line 53
    .line 54
    check-cast p0, Lq3/d;

    .line 55
    .line 56
    invoke-static {p1, p2}, Lt4/q;->c(J)F

    .line 57
    .line 58
    .line 59
    move-result p1

    .line 60
    invoke-virtual {p0, p1}, Lq3/d;->b(F)F

    .line 61
    .line 62
    .line 63
    move-result p0

    .line 64
    invoke-static {v0, p0}, Lkp/g9;->a(FF)J

    .line 65
    .line 66
    .line 67
    move-result-wide p0

    .line 68
    return-wide p0
.end method

.method public g()V
    .locals 4

    .line 1
    iget-object v0, p0, Lh6/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lq3/d;

    .line 4
    .line 5
    iget-object v1, v0, Lq3/d;->d:[Lq3/a;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    invoke-static {v1, v2}, Lmx0/n;->s([Ljava/lang/Object;Lj51/i;)V

    .line 9
    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    iput v1, v0, Lq3/d;->e:I

    .line 13
    .line 14
    iget-object v0, p0, Lh6/j;->f:Ljava/lang/Object;

    .line 15
    .line 16
    check-cast v0, Lq3/d;

    .line 17
    .line 18
    iget-object v3, v0, Lq3/d;->d:[Lq3/a;

    .line 19
    .line 20
    invoke-static {v3, v2}, Lmx0/n;->s([Ljava/lang/Object;Lj51/i;)V

    .line 21
    .line 22
    .line 23
    iput v1, v0, Lq3/d;->e:I

    .line 24
    .line 25
    const-wide/16 v0, 0x0

    .line 26
    .line 27
    iput-wide v0, p0, Lh6/j;->d:J

    .line 28
    .line 29
    return-void
.end method

.method public h(Lhm/a;Lyl/j;Ljava/util/Map;J)V
    .locals 6

    .line 1
    iget-object v0, p0, Lh6/j;->f:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast v0, Lc1/i2;

    .line 4
    .line 5
    iget-wide v1, v0, Lc1/i2;->d:J

    .line 6
    .line 7
    iget-object v3, v0, Lc1/i2;->f:Ljava/lang/Object;

    .line 8
    .line 9
    check-cast v3, Ljava/util/LinkedHashMap;

    .line 10
    .line 11
    cmp-long v1, p4, v1

    .line 12
    .line 13
    if-gtz v1, :cond_1

    .line 14
    .line 15
    new-instance p0, Lhm/e;

    .line 16
    .line 17
    invoke-direct {p0, p2, p3, p4, p5}, Lhm/e;-><init>(Lyl/j;Ljava/util/Map;J)V

    .line 18
    .line 19
    .line 20
    invoke-interface {v3, p1, p0}, Ljava/util/Map;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 21
    .line 22
    .line 23
    move-result-object p2

    .line 24
    invoke-virtual {v0}, Lc1/i2;->c()J

    .line 25
    .line 26
    .line 27
    move-result-wide p3

    .line 28
    invoke-virtual {v0, p1, p0}, Lc1/i2;->f(Ljava/lang/Object;Ljava/lang/Object;)J

    .line 29
    .line 30
    .line 31
    move-result-wide v1

    .line 32
    add-long/2addr v1, p3

    .line 33
    iput-wide v1, v0, Lc1/i2;->e:J

    .line 34
    .line 35
    if-eqz p2, :cond_0

    .line 36
    .line 37
    invoke-virtual {v0}, Lc1/i2;->c()J

    .line 38
    .line 39
    .line 40
    move-result-wide p3

    .line 41
    invoke-virtual {v0, p1, p2}, Lc1/i2;->f(Ljava/lang/Object;Ljava/lang/Object;)J

    .line 42
    .line 43
    .line 44
    move-result-wide v1

    .line 45
    sub-long/2addr p3, v1

    .line 46
    iput-wide p3, v0, Lc1/i2;->e:J

    .line 47
    .line 48
    invoke-virtual {v0, p1, p2, p0}, Lc1/i2;->b(Ljava/lang/Object;Ljava/lang/Object;Lhm/e;)V

    .line 49
    .line 50
    .line 51
    :cond_0
    iget-wide p0, v0, Lc1/i2;->d:J

    .line 52
    .line 53
    invoke-virtual {v0, p0, p1}, Lc1/i2;->g(J)V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :cond_1
    invoke-interface {v3, p1}, Ljava/util/Map;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    if-eqz v1, :cond_2

    .line 62
    .line 63
    invoke-virtual {v0}, Lc1/i2;->c()J

    .line 64
    .line 65
    .line 66
    move-result-wide v2

    .line 67
    invoke-virtual {v0, p1, v1}, Lc1/i2;->f(Ljava/lang/Object;Ljava/lang/Object;)J

    .line 68
    .line 69
    .line 70
    move-result-wide v4

    .line 71
    sub-long/2addr v2, v4

    .line 72
    iput-wide v2, v0, Lc1/i2;->e:J

    .line 73
    .line 74
    const/4 v2, 0x0

    .line 75
    invoke-virtual {v0, p1, v1, v2}, Lc1/i2;->b(Ljava/lang/Object;Ljava/lang/Object;Lhm/e;)V

    .line 76
    .line 77
    .line 78
    :cond_2
    iget-object p0, p0, Lh6/j;->e:Ljava/lang/Object;

    .line 79
    .line 80
    move-object v0, p0

    .line 81
    check-cast v0, Lhm/g;

    .line 82
    .line 83
    move-object v1, p1

    .line 84
    move-object v2, p2

    .line 85
    move-object v3, p3

    .line 86
    move-wide v4, p4

    .line 87
    invoke-virtual/range {v0 .. v5}, Lhm/g;->c(Lhm/a;Lyl/j;Ljava/util/Map;J)V

    .line 88
    .line 89
    .line 90
    return-void
.end method

.method public i()Lh0/q;
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh0/s;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-interface {p0}, Lh0/s;->i()Lh0/q;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Lh0/q;->d:Lh0/q;

    .line 13
    .line 14
    return-object p0
.end method

.method public j()Ljava/util/List;
    .locals 21

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    iget-object v0, v1, Lh6/j;->e:Ljava/lang/Object;

    .line 4
    .line 5
    move-object v2, v0

    .line 6
    check-cast v2, Lvp/n;

    .line 7
    .line 8
    new-instance v3, Ljava/util/ArrayList;

    .line 9
    .line 10
    invoke-direct {v3}, Ljava/util/ArrayList;-><init>()V

    .line 11
    .line 12
    .line 13
    iget-object v0, v1, Lh6/j;->f:Ljava/lang/Object;

    .line 14
    .line 15
    move-object v4, v0

    .line 16
    check-cast v4, Ljava/lang/String;

    .line 17
    .line 18
    iget-wide v5, v1, Lh6/j;->d:J

    .line 19
    .line 20
    invoke-static {v5, v6}, Ljava/lang/String;->valueOf(J)Ljava/lang/String;

    .line 21
    .line 22
    .line 23
    move-result-object v0

    .line 24
    filled-new-array {v4, v0}, [Ljava/lang/String;

    .line 25
    .line 26
    .line 27
    move-result-object v9

    .line 28
    const-string v8, "app_id = ? and rowid > ?"

    .line 29
    .line 30
    const-string v13, "1000"

    .line 31
    .line 32
    const/4 v14, 0x0

    .line 33
    :try_start_0
    invoke-virtual {v2}, Lvp/n;->P0()Landroid/database/sqlite/SQLiteDatabase;

    .line 34
    .line 35
    .line 36
    move-result-object v5

    .line 37
    const-string v6, "raw_events"

    .line 38
    .line 39
    const-string v15, "rowid"

    .line 40
    .line 41
    const-string v16, "name"

    .line 42
    .line 43
    const-string v17, "timestamp"

    .line 44
    .line 45
    const-string v18, "metadata_fingerprint"

    .line 46
    .line 47
    const-string v19, "data"

    .line 48
    .line 49
    const-string v20, "realtime"

    .line 50
    .line 51
    filled-new-array/range {v15 .. v20}, [Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object v7

    .line 55
    const-string v12, "rowid"

    .line 56
    .line 57
    const/4 v10, 0x0

    .line 58
    const/4 v11, 0x0

    .line 59
    invoke-virtual/range {v5 .. v13}, Landroid/database/sqlite/SQLiteDatabase;->query(Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;

    .line 60
    .line 61
    .line 62
    move-result-object v14

    .line 63
    invoke-interface {v14}, Landroid/database/Cursor;->moveToFirst()Z

    .line 64
    .line 65
    .line 66
    move-result v0

    .line 67
    if-eqz v0, :cond_4

    .line 68
    .line 69
    :cond_0
    const/4 v0, 0x0

    .line 70
    invoke-interface {v14, v0}, Landroid/database/Cursor;->getLong(I)J

    .line 71
    .line 72
    .line 73
    move-result-wide v6

    .line 74
    const/4 v5, 0x3

    .line 75
    invoke-interface {v14, v5}, Landroid/database/Cursor;->getLong(I)J

    .line 76
    .line 77
    .line 78
    move-result-wide v8

    .line 79
    const/4 v5, 0x5

    .line 80
    invoke-interface {v14, v5}, Landroid/database/Cursor;->getLong(I)J

    .line 81
    .line 82
    .line 83
    move-result-wide v10

    .line 84
    const-wide/16 v12, 0x1

    .line 85
    .line 86
    cmp-long v5, v10, v12

    .line 87
    .line 88
    const/4 v10, 0x1

    .line 89
    if-nez v5, :cond_1

    .line 90
    .line 91
    move v0, v10

    .line 92
    :cond_1
    const/4 v5, 0x4

    .line 93
    invoke-interface {v14, v5}, Landroid/database/Cursor;->getBlob(I)[B

    .line 94
    .line 95
    .line 96
    move-result-object v5

    .line 97
    iget-wide v11, v1, Lh6/j;->d:J

    .line 98
    .line 99
    cmp-long v11, v6, v11

    .line 100
    .line 101
    if-lez v11, :cond_2

    .line 102
    .line 103
    iput-wide v6, v1, Lh6/j;->d:J
    :try_end_0
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_0 .. :try_end_0} :catch_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 104
    .line 105
    :cond_2
    :try_start_1
    invoke-static {}, Lcom/google/android/gms/internal/measurement/b3;->z()Lcom/google/android/gms/internal/measurement/a3;

    .line 106
    .line 107
    .line 108
    move-result-object v11

    .line 109
    invoke-static {v11, v5}, Lvp/s0;->N0(Lcom/google/android/gms/internal/measurement/k5;[B)Lcom/google/android/gms/internal/measurement/k5;

    .line 110
    .line 111
    .line 112
    move-result-object v5

    .line 113
    check-cast v5, Lcom/google/android/gms/internal/measurement/a3;
    :try_end_1
    .catch Ljava/io/IOException; {:try_start_1 .. :try_end_1} :catch_1
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_1 .. :try_end_1} :catch_0
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 114
    .line 115
    :try_start_2
    invoke-interface {v14, v10}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;

    .line 116
    .line 117
    .line 118
    move-result-object v10

    .line 119
    if-nez v10, :cond_3

    .line 120
    .line 121
    const-string v10, ""

    .line 122
    .line 123
    :cond_3
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 124
    .line 125
    .line 126
    iget-object v11, v5, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 127
    .line 128
    check-cast v11, Lcom/google/android/gms/internal/measurement/b3;

    .line 129
    .line 130
    invoke-virtual {v11, v10}, Lcom/google/android/gms/internal/measurement/b3;->F(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    const/4 v10, 0x2

    .line 134
    invoke-interface {v14, v10}, Landroid/database/Cursor;->getLong(I)J

    .line 135
    .line 136
    .line 137
    move-result-wide v10

    .line 138
    invoke-virtual {v5}, Lcom/google/android/gms/internal/measurement/k5;->b()V

    .line 139
    .line 140
    .line 141
    iget-object v12, v5, Lcom/google/android/gms/internal/measurement/k5;->e:Lcom/google/android/gms/internal/measurement/l5;

    .line 142
    .line 143
    check-cast v12, Lcom/google/android/gms/internal/measurement/b3;

    .line 144
    .line 145
    invoke-virtual {v12, v10, v11}, Lcom/google/android/gms/internal/measurement/b3;->G(J)V

    .line 146
    .line 147
    .line 148
    move-object v10, v5

    .line 149
    new-instance v5, Lvp/l;

    .line 150
    .line 151
    invoke-virtual {v10}, Lcom/google/android/gms/internal/measurement/k5;->e()Lcom/google/android/gms/internal/measurement/l5;

    .line 152
    .line 153
    .line 154
    move-result-object v10

    .line 155
    move-object v11, v10

    .line 156
    check-cast v11, Lcom/google/android/gms/internal/measurement/b3;

    .line 157
    .line 158
    move v10, v0

    .line 159
    invoke-direct/range {v5 .. v11}, Lvp/l;-><init>(JJZLcom/google/android/gms/internal/measurement/b3;)V

    .line 160
    .line 161
    .line 162
    invoke-virtual {v3, v5}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 163
    .line 164
    .line 165
    goto :goto_0

    .line 166
    :catchall_0
    move-exception v0

    .line 167
    goto :goto_3

    .line 168
    :catch_0
    move-exception v0

    .line 169
    goto :goto_1

    .line 170
    :catch_1
    move-exception v0

    .line 171
    iget-object v5, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 172
    .line 173
    check-cast v5, Lvp/g1;

    .line 174
    .line 175
    iget-object v5, v5, Lvp/g1;->i:Lvp/p0;

    .line 176
    .line 177
    invoke-static {v5}, Lvp/g1;->k(Lvp/n1;)V

    .line 178
    .line 179
    .line 180
    iget-object v5, v5, Lvp/p0;->j:Lvp/n0;

    .line 181
    .line 182
    const-string v6, "Data loss. Failed to merge raw event. appId"

    .line 183
    .line 184
    invoke-static {v4}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 185
    .line 186
    .line 187
    move-result-object v7

    .line 188
    invoke-virtual {v5, v7, v0, v6}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V

    .line 189
    .line 190
    .line 191
    :goto_0
    invoke-interface {v14}, Landroid/database/Cursor;->moveToNext()Z

    .line 192
    .line 193
    .line 194
    move-result v0

    .line 195
    if-nez v0, :cond_0

    .line 196
    .line 197
    goto :goto_2

    .line 198
    :cond_4
    sget-object v3, Ljava/util/Collections;->EMPTY_LIST:Ljava/util/List;
    :try_end_2
    .catch Landroid/database/sqlite/SQLiteException; {:try_start_2 .. :try_end_2} :catch_0
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 199
    .line 200
    goto :goto_2

    .line 201
    :goto_1
    :try_start_3
    iget-object v1, v2, Lap0/o;->e:Ljava/lang/Object;

    .line 202
    .line 203
    check-cast v1, Lvp/g1;

    .line 204
    .line 205
    iget-object v1, v1, Lvp/g1;->i:Lvp/p0;

    .line 206
    .line 207
    invoke-static {v1}, Lvp/g1;->k(Lvp/n1;)V

    .line 208
    .line 209
    .line 210
    iget-object v1, v1, Lvp/p0;->j:Lvp/n0;

    .line 211
    .line 212
    const-string v2, "Data loss. Error querying raw events batch. appId"

    .line 213
    .line 214
    invoke-static {v4}, Lvp/p0;->i0(Ljava/lang/String;)Lvp/o0;

    .line 215
    .line 216
    .line 217
    move-result-object v4

    .line 218
    invoke-virtual {v1, v4, v0, v2}, Lvp/n0;->c(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/String;)V
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_0

    .line 219
    .line 220
    .line 221
    :goto_2
    if-eqz v14, :cond_5

    .line 222
    .line 223
    invoke-interface {v14}, Landroid/database/Cursor;->close()V

    .line 224
    .line 225
    .line 226
    :cond_5
    return-object v3

    .line 227
    :goto_3
    if-eqz v14, :cond_6

    .line 228
    .line 229
    invoke-interface {v14}, Landroid/database/Cursor;->close()V

    .line 230
    .line 231
    .line 232
    :cond_6
    throw v0
.end method

.method public k()Lh0/r;
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh0/s;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-interface {p0}, Lh0/s;->k()Lh0/r;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Lh0/r;->d:Lh0/r;

    .line 13
    .line 14
    return-object p0
.end method

.method public m()Lh0/p;
    .locals 0

    .line 1
    iget-object p0, p0, Lh6/j;->e:Ljava/lang/Object;

    .line 2
    .line 3
    check-cast p0, Lh0/s;

    .line 4
    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-interface {p0}, Lh0/s;->m()Lh0/p;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    sget-object p0, Lh0/p;->d:Lh0/p;

    .line 13
    .line 14
    return-object p0
.end method
