.class public final Lx4/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lx4/v;


# instance fields
.field public final d:Lx2/j;

.field public final e:J


# direct methods
.method public constructor <init>(Lx2/j;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lx4/a;->d:Lx2/j;

    .line 5
    .line 6
    iput-wide p2, p0, Lx4/a;->e:J

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final F(Lt4/k;JLt4/m;J)J
    .locals 20

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    invoke-virtual/range {p1 .. p1}, Lt4/k;->d()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    invoke-virtual/range {p1 .. p1}, Lt4/k;->b()I

    .line 8
    .line 9
    .line 10
    move-result v2

    .line 11
    int-to-long v3, v1

    .line 12
    const/16 v1, 0x20

    .line 13
    .line 14
    shl-long/2addr v3, v1

    .line 15
    int-to-long v5, v2

    .line 16
    const-wide v7, 0xffffffffL

    .line 17
    .line 18
    .line 19
    .line 20
    .line 21
    and-long/2addr v5, v7

    .line 22
    or-long v12, v3, v5

    .line 23
    .line 24
    iget-object v9, v0, Lx4/a;->d:Lx2/j;

    .line 25
    .line 26
    const-wide/16 v10, 0x0

    .line 27
    .line 28
    move-object/from16 v14, p4

    .line 29
    .line 30
    invoke-virtual/range {v9 .. v14}, Lx2/j;->a(JJLt4/m;)J

    .line 31
    .line 32
    .line 33
    move-result-wide v2

    .line 34
    const-wide/16 v15, 0x0

    .line 35
    .line 36
    move-object/from16 v19, p4

    .line 37
    .line 38
    move-wide/from16 v17, p5

    .line 39
    .line 40
    move-object v14, v9

    .line 41
    invoke-virtual/range {v14 .. v19}, Lx2/j;->a(JJLt4/m;)J

    .line 42
    .line 43
    .line 44
    move-result-wide v4

    .line 45
    shr-long v9, v4, v1

    .line 46
    .line 47
    long-to-int v6, v9

    .line 48
    neg-int v6, v6

    .line 49
    and-long/2addr v4, v7

    .line 50
    long-to-int v4, v4

    .line 51
    neg-int v4, v4

    .line 52
    int-to-long v5, v6

    .line 53
    shl-long/2addr v5, v1

    .line 54
    int-to-long v9, v4

    .line 55
    and-long/2addr v9, v7

    .line 56
    or-long v4, v5, v9

    .line 57
    .line 58
    iget-wide v9, v0, Lx4/a;->e:J

    .line 59
    .line 60
    shr-long v11, v9, v1

    .line 61
    .line 62
    long-to-int v0, v11

    .line 63
    sget-object v6, Lt4/m;->d:Lt4/m;

    .line 64
    .line 65
    move-object/from16 v14, p4

    .line 66
    .line 67
    if-ne v14, v6, :cond_0

    .line 68
    .line 69
    const/4 v6, 0x1

    .line 70
    goto :goto_0

    .line 71
    :cond_0
    const/4 v6, -0x1

    .line 72
    :goto_0
    mul-int/2addr v0, v6

    .line 73
    and-long/2addr v9, v7

    .line 74
    long-to-int v6, v9

    .line 75
    int-to-long v9, v0

    .line 76
    shl-long v0, v9, v1

    .line 77
    .line 78
    int-to-long v9, v6

    .line 79
    and-long v6, v9, v7

    .line 80
    .line 81
    or-long/2addr v0, v6

    .line 82
    invoke-virtual/range {p1 .. p1}, Lt4/k;->c()J

    .line 83
    .line 84
    .line 85
    move-result-wide v6

    .line 86
    invoke-static {v6, v7, v2, v3}, Lt4/j;->d(JJ)J

    .line 87
    .line 88
    .line 89
    move-result-wide v2

    .line 90
    invoke-static {v2, v3, v4, v5}, Lt4/j;->d(JJ)J

    .line 91
    .line 92
    .line 93
    move-result-wide v2

    .line 94
    invoke-static {v2, v3, v0, v1}, Lt4/j;->d(JJ)J

    .line 95
    .line 96
    .line 97
    move-result-wide v0

    .line 98
    return-wide v0
.end method
