.class public final Lbe0/a;
.super Li3/c;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final i:Li3/c;

.field public final j:J

.field public final k:J


# direct methods
.method public constructor <init>(Li3/c;JJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Li3/c;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lbe0/a;->i:Li3/c;

    .line 5
    .line 6
    iput-wide p2, p0, Lbe0/a;->j:J

    .line 7
    .line 8
    iput-wide p4, p0, Lbe0/a;->k:J

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final g()J
    .locals 2

    .line 1
    iget-object p0, p0, Lbe0/a;->i:Li3/c;

    .line 2
    .line 3
    invoke-virtual {p0}, Li3/c;->g()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    return-wide v0
.end method

.method public final i(Lg3/d;)V
    .locals 13

    .line 1
    const-string v1, "<this>"

    .line 2
    .line 3
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/4 v11, 0x0

    .line 7
    const/16 v12, 0x7e

    .line 8
    .line 9
    iget-wide v3, p0, Lbe0/a;->k:J

    .line 10
    .line 11
    const-wide/16 v5, 0x0

    .line 12
    .line 13
    const-wide/16 v7, 0x0

    .line 14
    .line 15
    const/4 v9, 0x0

    .line 16
    const/4 v10, 0x0

    .line 17
    move-object v2, p1

    .line 18
    invoke-static/range {v2 .. v12}, Lg3/d;->r0(Lg3/d;JJJFLg3/h;Le3/m;I)V

    .line 19
    .line 20
    .line 21
    iget-object v2, p0, Lbe0/a;->i:Li3/c;

    .line 22
    .line 23
    invoke-interface {p1}, Lg3/d;->e()J

    .line 24
    .line 25
    .line 26
    move-result-wide v3

    .line 27
    const/16 v1, 0x20

    .line 28
    .line 29
    shr-long/2addr v3, v1

    .line 30
    long-to-int v1, v3

    .line 31
    invoke-static {v1}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 32
    .line 33
    .line 34
    move-result v1

    .line 35
    const/high16 v3, 0x3e800000    # 0.25f

    .line 36
    .line 37
    mul-float/2addr v1, v3

    .line 38
    invoke-interface {p1}, Lg3/d;->e()J

    .line 39
    .line 40
    .line 41
    move-result-wide v4

    .line 42
    const-wide v6, 0xffffffffL

    .line 43
    .line 44
    .line 45
    .line 46
    .line 47
    and-long/2addr v4, v6

    .line 48
    long-to-int v4, v4

    .line 49
    invoke-static {v4}, Ljava/lang/Float;->intBitsToFloat(I)F

    .line 50
    .line 51
    .line 52
    move-result v4

    .line 53
    mul-float v8, v4, v3

    .line 54
    .line 55
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 56
    .line 57
    .line 58
    move-result-object v3

    .line 59
    iget-object v3, v3, Lgw0/c;->e:Ljava/lang/Object;

    .line 60
    .line 61
    check-cast v3, Lbu/c;

    .line 62
    .line 63
    invoke-virtual {v3, v1, v8, v1, v8}, Lbu/c;->v(FFFF)V

    .line 64
    .line 65
    .line 66
    :try_start_0
    invoke-interface {p1}, Lg3/d;->e()J

    .line 67
    .line 68
    .line 69
    move-result-wide v4

    .line 70
    iget-wide v6, p0, Lbe0/a;->j:J

    .line 71
    .line 72
    new-instance v0, Le3/m;

    .line 73
    .line 74
    const/4 v3, 0x5

    .line 75
    invoke-direct {v0, v6, v7, v3}, Le3/m;-><init>(JI)V

    .line 76
    .line 77
    .line 78
    const/high16 v6, 0x3f800000    # 1.0f

    .line 79
    .line 80
    move-object v3, p1

    .line 81
    move-object v7, v0

    .line 82
    invoke-virtual/range {v2 .. v7}, Li3/c;->f(Lg3/d;JFLe3/m;)V
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 83
    .line 84
    .line 85
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 86
    .line 87
    .line 88
    move-result-object v0

    .line 89
    iget-object v0, v0, Lgw0/c;->e:Ljava/lang/Object;

    .line 90
    .line 91
    check-cast v0, Lbu/c;

    .line 92
    .line 93
    neg-float v1, v1

    .line 94
    neg-float v2, v8

    .line 95
    invoke-virtual {v0, v1, v2, v1, v2}, Lbu/c;->v(FFFF)V

    .line 96
    .line 97
    .line 98
    return-void

    .line 99
    :catchall_0
    move-exception v0

    .line 100
    invoke-interface {p1}, Lg3/d;->x0()Lgw0/c;

    .line 101
    .line 102
    .line 103
    move-result-object v2

    .line 104
    iget-object v2, v2, Lgw0/c;->e:Ljava/lang/Object;

    .line 105
    .line 106
    check-cast v2, Lbu/c;

    .line 107
    .line 108
    neg-float v1, v1

    .line 109
    neg-float v3, v8

    .line 110
    invoke-virtual {v2, v1, v3, v1, v3}, Lbu/c;->v(FFFF)V

    .line 111
    .line 112
    .line 113
    throw v0
.end method
