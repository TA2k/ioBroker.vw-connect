.class public final Laz0/l;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

.field public static final synthetic f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

.field public static final g:Lj51/i;


# instance fields
.field private volatile synthetic _next$volatile:Ljava/lang/Object;

.field private volatile synthetic _state$volatile:J

.field public final a:I

.field public final b:Z

.field public final c:I

.field public final synthetic d:Ljava/util/concurrent/atomic/AtomicReferenceArray;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const-class v0, Ljava/lang/Object;

    .line 2
    .line 3
    const-string v1, "_next$volatile"

    .line 4
    .line 5
    const-class v2, Laz0/l;

    .line 6
    .line 7
    invoke-static {v2, v0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Laz0/l;->e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 12
    .line 13
    const-string v0, "_state$volatile"

    .line 14
    .line 15
    invoke-static {v2, v0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->newUpdater(Ljava/lang/Class;Ljava/lang/String;)Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    sput-object v0, Laz0/l;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 20
    .line 21
    new-instance v0, Lj51/i;

    .line 22
    .line 23
    const-string v1, "REMOVE_FROZEN"

    .line 24
    .line 25
    const/4 v2, 0x1

    .line 26
    invoke-direct {v0, v1, v2}, Lj51/i;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Laz0/l;->g:Lj51/i;

    .line 30
    .line 31
    return-void
.end method

.method public constructor <init>(IZ)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Laz0/l;->a:I

    .line 5
    .line 6
    iput-boolean p2, p0, Laz0/l;->b:Z

    .line 7
    .line 8
    add-int/lit8 p2, p1, -0x1

    .line 9
    .line 10
    iput p2, p0, Laz0/l;->c:I

    .line 11
    .line 12
    new-instance v0, Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 13
    .line 14
    invoke-direct {v0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;-><init>(I)V

    .line 15
    .line 16
    .line 17
    iput-object v0, p0, Laz0/l;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 18
    .line 19
    const p0, 0x3fffffff    # 1.9999999f

    .line 20
    .line 21
    .line 22
    const-string v0, "Check failed."

    .line 23
    .line 24
    if-gt p2, p0, :cond_1

    .line 25
    .line 26
    and-int p0, p1, p2

    .line 27
    .line 28
    if-nez p0, :cond_0

    .line 29
    .line 30
    return-void

    .line 31
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 32
    .line 33
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0

    .line 37
    :cond_1
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 38
    .line 39
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 40
    .line 41
    .line 42
    throw p0
.end method


# virtual methods
.method public final a(Ljava/lang/Object;)I
    .locals 14

    .line 1
    :cond_0
    :goto_0
    sget-object v0, Laz0/l;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v3

    .line 7
    const-wide/high16 v1, 0x3000000000000000L    # 1.727233711018889E-77

    .line 8
    .line 9
    and-long/2addr v1, v3

    .line 10
    const-wide/16 v7, 0x0

    .line 11
    .line 12
    cmp-long v1, v1, v7

    .line 13
    .line 14
    if-eqz v1, :cond_1

    .line 15
    .line 16
    const-wide/high16 p0, 0x2000000000000000L

    .line 17
    .line 18
    and-long/2addr p0, v3

    .line 19
    cmp-long p0, p0, v7

    .line 20
    .line 21
    if-eqz p0, :cond_3

    .line 22
    .line 23
    const/4 p0, 0x2

    .line 24
    return p0

    .line 25
    :cond_1
    const-wide/32 v1, 0x3fffffff

    .line 26
    .line 27
    .line 28
    and-long/2addr v1, v3

    .line 29
    long-to-int v1, v1

    .line 30
    const-wide v5, 0xfffffffc0000000L

    .line 31
    .line 32
    .line 33
    .line 34
    .line 35
    and-long/2addr v5, v3

    .line 36
    const/16 v2, 0x1e

    .line 37
    .line 38
    shr-long/2addr v5, v2

    .line 39
    long-to-int v9, v5

    .line 40
    add-int/lit8 v5, v9, 0x2

    .line 41
    .line 42
    iget v10, p0, Laz0/l;->c:I

    .line 43
    .line 44
    and-int/2addr v5, v10

    .line 45
    and-int v6, v1, v10

    .line 46
    .line 47
    if-ne v5, v6, :cond_2

    .line 48
    .line 49
    goto :goto_1

    .line 50
    :cond_2
    iget-boolean v5, p0, Laz0/l;->b:Z

    .line 51
    .line 52
    const v6, 0x3fffffff    # 1.9999999f

    .line 53
    .line 54
    .line 55
    iget-object v11, p0, Laz0/l;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 56
    .line 57
    if-nez v5, :cond_4

    .line 58
    .line 59
    and-int v5, v9, v10

    .line 60
    .line 61
    invoke-virtual {v11, v5}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 62
    .line 63
    .line 64
    move-result-object v5

    .line 65
    if-eqz v5, :cond_4

    .line 66
    .line 67
    const/16 v0, 0x400

    .line 68
    .line 69
    iget v2, p0, Laz0/l;->a:I

    .line 70
    .line 71
    if-lt v2, v0, :cond_3

    .line 72
    .line 73
    sub-int/2addr v9, v1

    .line 74
    and-int v0, v9, v6

    .line 75
    .line 76
    shr-int/lit8 v1, v2, 0x1

    .line 77
    .line 78
    if-le v0, v1, :cond_0

    .line 79
    .line 80
    :cond_3
    :goto_1
    const/4 p0, 0x1

    .line 81
    return p0

    .line 82
    :cond_4
    add-int/lit8 v1, v9, 0x1

    .line 83
    .line 84
    and-int/2addr v1, v6

    .line 85
    const-wide v5, -0xfffffffc0000001L    # -3.1050369248997324E231

    .line 86
    .line 87
    .line 88
    .line 89
    .line 90
    and-long/2addr v5, v3

    .line 91
    int-to-long v12, v1

    .line 92
    shl-long v1, v12, v2

    .line 93
    .line 94
    or-long/2addr v5, v1

    .line 95
    sget-object v1, Laz0/l;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 96
    .line 97
    move-object v2, p0

    .line 98
    invoke-virtual/range {v1 .. v6}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 99
    .line 100
    .line 101
    move-result p0

    .line 102
    if-eqz p0, :cond_8

    .line 103
    .line 104
    and-int p0, v9, v10

    .line 105
    .line 106
    invoke-virtual {v11, p0, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    .line 107
    .line 108
    .line 109
    move-object p0, v2

    .line 110
    :cond_5
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 111
    .line 112
    .line 113
    move-result-wide v1

    .line 114
    const-wide/high16 v3, 0x1000000000000000L

    .line 115
    .line 116
    and-long/2addr v1, v3

    .line 117
    cmp-long v1, v1, v7

    .line 118
    .line 119
    if-eqz v1, :cond_7

    .line 120
    .line 121
    invoke-virtual {p0}, Laz0/l;->c()Laz0/l;

    .line 122
    .line 123
    .line 124
    move-result-object p0

    .line 125
    iget-object v1, p0, Laz0/l;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 126
    .line 127
    iget v2, p0, Laz0/l;->c:I

    .line 128
    .line 129
    and-int/2addr v2, v9

    .line 130
    invoke-virtual {v1, v2}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 131
    .line 132
    .line 133
    move-result-object v3

    .line 134
    instance-of v4, v3, Laz0/k;

    .line 135
    .line 136
    if-eqz v4, :cond_6

    .line 137
    .line 138
    check-cast v3, Laz0/k;

    .line 139
    .line 140
    iget v3, v3, Laz0/k;->a:I

    .line 141
    .line 142
    if-ne v3, v9, :cond_6

    .line 143
    .line 144
    invoke-virtual {v1, v2, p1}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    .line 145
    .line 146
    .line 147
    goto :goto_2

    .line 148
    :cond_6
    const/4 p0, 0x0

    .line 149
    :goto_2
    if-nez p0, :cond_5

    .line 150
    .line 151
    :cond_7
    const/4 p0, 0x0

    .line 152
    return p0

    .line 153
    :cond_8
    move-object p0, v2

    .line 154
    goto/16 :goto_0
.end method

.method public final b()Z
    .locals 12

    .line 1
    :goto_0
    sget-object v0, Laz0/l;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    const-wide/high16 v4, 0x2000000000000000L

    .line 8
    .line 9
    and-long v6, v2, v4

    .line 10
    .line 11
    const-wide/16 v8, 0x0

    .line 12
    .line 13
    cmp-long v1, v6, v8

    .line 14
    .line 15
    const/4 v6, 0x1

    .line 16
    if-eqz v1, :cond_0

    .line 17
    .line 18
    return v6

    .line 19
    :cond_0
    const-wide/high16 v10, 0x1000000000000000L

    .line 20
    .line 21
    and-long/2addr v10, v2

    .line 22
    cmp-long v1, v10, v8

    .line 23
    .line 24
    if-eqz v1, :cond_1

    .line 25
    .line 26
    const/4 p0, 0x0

    .line 27
    return p0

    .line 28
    :cond_1
    or-long/2addr v4, v2

    .line 29
    move-object v1, p0

    .line 30
    invoke-virtual/range {v0 .. v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_2

    .line 35
    .line 36
    return v6

    .line 37
    :cond_2
    move-object p0, v1

    .line 38
    goto :goto_0
.end method

.method public final c()Laz0/l;
    .locals 10

    .line 1
    :goto_0
    sget-object v0, Laz0/l;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 2
    .line 3
    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    const-wide/high16 v4, 0x1000000000000000L

    .line 8
    .line 9
    and-long v6, v2, v4

    .line 10
    .line 11
    const-wide/16 v8, 0x0

    .line 12
    .line 13
    cmp-long v1, v6, v8

    .line 14
    .line 15
    if-eqz v1, :cond_0

    .line 16
    .line 17
    move-object v1, p0

    .line 18
    goto :goto_1

    .line 19
    :cond_0
    or-long/2addr v4, v2

    .line 20
    move-object v1, p0

    .line 21
    invoke-virtual/range {v0 .. v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 22
    .line 23
    .line 24
    move-result p0

    .line 25
    if-eqz p0, :cond_6

    .line 26
    .line 27
    move-wide v2, v4

    .line 28
    :goto_1
    sget-object p0, Laz0/l;->e:Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;

    .line 29
    .line 30
    invoke-virtual {p0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 31
    .line 32
    .line 33
    move-result-object v4

    .line 34
    check-cast v4, Laz0/l;

    .line 35
    .line 36
    if-eqz v4, :cond_1

    .line 37
    .line 38
    return-object v4

    .line 39
    :cond_1
    new-instance v4, Laz0/l;

    .line 40
    .line 41
    iget v5, v1, Laz0/l;->a:I

    .line 42
    .line 43
    mul-int/lit8 v5, v5, 0x2

    .line 44
    .line 45
    iget-boolean v6, v1, Laz0/l;->b:Z

    .line 46
    .line 47
    invoke-direct {v4, v5, v6}, Laz0/l;-><init>(IZ)V

    .line 48
    .line 49
    .line 50
    const-wide/32 v5, 0x3fffffff

    .line 51
    .line 52
    .line 53
    and-long/2addr v5, v2

    .line 54
    long-to-int v5, v5

    .line 55
    const-wide v6, 0xfffffffc0000000L

    .line 56
    .line 57
    .line 58
    .line 59
    .line 60
    and-long/2addr v6, v2

    .line 61
    const/16 v8, 0x1e

    .line 62
    .line 63
    shr-long/2addr v6, v8

    .line 64
    long-to-int v6, v6

    .line 65
    :goto_2
    iget v7, v1, Laz0/l;->c:I

    .line 66
    .line 67
    and-int v8, v5, v7

    .line 68
    .line 69
    and-int/2addr v7, v6

    .line 70
    if-eq v8, v7, :cond_3

    .line 71
    .line 72
    iget-object v7, v1, Laz0/l;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 73
    .line 74
    invoke-virtual {v7, v8}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 75
    .line 76
    .line 77
    move-result-object v7

    .line 78
    if-nez v7, :cond_2

    .line 79
    .line 80
    new-instance v7, Laz0/k;

    .line 81
    .line 82
    invoke-direct {v7, v5}, Laz0/k;-><init>(I)V

    .line 83
    .line 84
    .line 85
    :cond_2
    iget v8, v4, Laz0/l;->c:I

    .line 86
    .line 87
    and-int/2addr v8, v5

    .line 88
    iget-object v9, v4, Laz0/l;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 89
    .line 90
    invoke-virtual {v9, v8, v7}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    .line 91
    .line 92
    .line 93
    add-int/lit8 v5, v5, 0x1

    .line 94
    .line 95
    goto :goto_2

    .line 96
    :cond_3
    const-wide v5, -0x1000000000000001L    # -3.1050361846014175E231

    .line 97
    .line 98
    .line 99
    .line 100
    .line 101
    and-long/2addr v5, v2

    .line 102
    invoke-virtual {v0, v4, v5, v6}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->set(Ljava/lang/Object;J)V

    .line 103
    .line 104
    .line 105
    :cond_4
    const/4 v5, 0x0

    .line 106
    invoke-virtual {p0, v1, v5, v4}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->compareAndSet(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 107
    .line 108
    .line 109
    move-result v5

    .line 110
    if-eqz v5, :cond_5

    .line 111
    .line 112
    goto :goto_1

    .line 113
    :cond_5
    invoke-virtual {p0, v1}, Ljava/util/concurrent/atomic/AtomicReferenceFieldUpdater;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 114
    .line 115
    .line 116
    move-result-object v5

    .line 117
    if-eqz v5, :cond_4

    .line 118
    .line 119
    goto :goto_1

    .line 120
    :cond_6
    move-object p0, v1

    .line 121
    goto :goto_0
.end method

.method public final d()Ljava/lang/Object;
    .locals 30

    .line 1
    move-object/from16 v1, p0

    .line 2
    .line 3
    :cond_0
    sget-object v6, Laz0/l;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 4
    .line 5
    invoke-virtual {v6, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    const-wide/high16 v7, 0x1000000000000000L

    .line 10
    .line 11
    and-long v4, v2, v7

    .line 12
    .line 13
    const-wide/16 v9, 0x0

    .line 14
    .line 15
    cmp-long v0, v4, v9

    .line 16
    .line 17
    if-eqz v0, :cond_1

    .line 18
    .line 19
    sget-object v0, Laz0/l;->g:Lj51/i;

    .line 20
    .line 21
    return-object v0

    .line 22
    :cond_1
    const-wide/32 v11, 0x3fffffff

    .line 23
    .line 24
    .line 25
    and-long v4, v2, v11

    .line 26
    .line 27
    long-to-int v0, v4

    .line 28
    const-wide v4, 0xfffffffc0000000L

    .line 29
    .line 30
    .line 31
    .line 32
    .line 33
    and-long/2addr v4, v2

    .line 34
    const/16 v13, 0x1e

    .line 35
    .line 36
    shr-long/2addr v4, v13

    .line 37
    long-to-int v4, v4

    .line 38
    iget v5, v1, Laz0/l;->c:I

    .line 39
    .line 40
    and-int/2addr v4, v5

    .line 41
    and-int v13, v0, v5

    .line 42
    .line 43
    const/4 v14, 0x0

    .line 44
    if-ne v4, v13, :cond_2

    .line 45
    .line 46
    goto :goto_0

    .line 47
    :cond_2
    iget-object v15, v1, Laz0/l;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 48
    .line 49
    invoke-virtual {v15, v13}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->get(I)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    move-result-object v4

    .line 53
    iget-boolean v5, v1, Laz0/l;->b:Z

    .line 54
    .line 55
    if-nez v4, :cond_3

    .line 56
    .line 57
    if-eqz v5, :cond_0

    .line 58
    .line 59
    goto :goto_0

    .line 60
    :cond_3
    move-wide/from16 v16, v7

    .line 61
    .line 62
    instance-of v7, v4, Laz0/k;

    .line 63
    .line 64
    if-eqz v7, :cond_4

    .line 65
    .line 66
    :goto_0
    return-object v14

    .line 67
    :cond_4
    add-int/lit8 v0, v0, 0x1

    .line 68
    .line 69
    const v7, 0x3fffffff    # 1.9999999f

    .line 70
    .line 71
    .line 72
    and-int/2addr v0, v7

    .line 73
    const-wide/32 v7, -0x40000000

    .line 74
    .line 75
    .line 76
    and-long v18, v2, v7

    .line 77
    .line 78
    move-wide/from16 v20, v7

    .line 79
    .line 80
    int-to-long v7, v0

    .line 81
    or-long v18, v18, v7

    .line 82
    .line 83
    sget-object v0, Laz0/l;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 84
    .line 85
    move-wide/from16 v28, v18

    .line 86
    .line 87
    move-object/from16 v18, v4

    .line 88
    .line 89
    move/from16 v19, v5

    .line 90
    .line 91
    move-wide/from16 v4, v28

    .line 92
    .line 93
    invoke-virtual/range {v0 .. v5}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 94
    .line 95
    .line 96
    move-result v0

    .line 97
    if-eqz v0, :cond_5

    .line 98
    .line 99
    invoke-virtual {v15, v13, v14}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    .line 100
    .line 101
    .line 102
    return-object v18

    .line 103
    :cond_5
    move-object/from16 v1, p0

    .line 104
    .line 105
    if-eqz v19, :cond_0

    .line 106
    .line 107
    :cond_6
    :goto_1
    invoke-virtual {v6, v1}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->get(Ljava/lang/Object;)J

    .line 108
    .line 109
    .line 110
    move-result-wide v24

    .line 111
    and-long v2, v24, v11

    .line 112
    .line 113
    long-to-int v0, v2

    .line 114
    and-long v2, v24, v16

    .line 115
    .line 116
    cmp-long v2, v2, v9

    .line 117
    .line 118
    if-eqz v2, :cond_7

    .line 119
    .line 120
    invoke-virtual {v1}, Laz0/l;->c()Laz0/l;

    .line 121
    .line 122
    .line 123
    move-result-object v0

    .line 124
    move-object v1, v0

    .line 125
    goto :goto_2

    .line 126
    :cond_7
    and-long v2, v24, v20

    .line 127
    .line 128
    or-long v26, v2, v7

    .line 129
    .line 130
    sget-object v22, Laz0/l;->f:Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;

    .line 131
    .line 132
    move-object/from16 v23, v1

    .line 133
    .line 134
    invoke-virtual/range {v22 .. v27}, Ljava/util/concurrent/atomic/AtomicLongFieldUpdater;->compareAndSet(Ljava/lang/Object;JJ)Z

    .line 135
    .line 136
    .line 137
    move-result v1

    .line 138
    move-object/from16 v2, v23

    .line 139
    .line 140
    if-eqz v1, :cond_8

    .line 141
    .line 142
    iget-object v1, v2, Laz0/l;->d:Ljava/util/concurrent/atomic/AtomicReferenceArray;

    .line 143
    .line 144
    iget v2, v2, Laz0/l;->c:I

    .line 145
    .line 146
    and-int/2addr v0, v2

    .line 147
    invoke-virtual {v1, v0, v14}, Ljava/util/concurrent/atomic/AtomicReferenceArray;->set(ILjava/lang/Object;)V

    .line 148
    .line 149
    .line 150
    move-object v1, v14

    .line 151
    :goto_2
    if-nez v1, :cond_6

    .line 152
    .line 153
    return-object v18

    .line 154
    :cond_8
    move-object v1, v2

    .line 155
    goto :goto_1
.end method
