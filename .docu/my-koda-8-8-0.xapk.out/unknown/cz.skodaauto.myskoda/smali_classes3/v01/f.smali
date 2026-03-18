.class public final Lv01/f;
.super Lu01/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final e:J

.field public final f:Z

.field public g:J


# direct methods
.method public constructor <init>(Lu01/h0;JZ)V
    .locals 0

    .line 1
    invoke-direct {p0, p1}, Lu01/n;-><init>(Lu01/h0;)V

    .line 2
    .line 3
    .line 4
    iput-wide p2, p0, Lv01/f;->e:J

    .line 5
    .line 6
    iput-boolean p4, p0, Lv01/f;->f:Z

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 9

    .line 1
    const-string v0, "sink"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-wide v0, p0, Lv01/f;->g:J

    .line 7
    .line 8
    iget-wide v2, p0, Lv01/f;->e:J

    .line 9
    .line 10
    cmp-long v4, v0, v2

    .line 11
    .line 12
    const-wide/16 v5, -0x1

    .line 13
    .line 14
    const-wide/16 v7, 0x0

    .line 15
    .line 16
    if-lez v4, :cond_0

    .line 17
    .line 18
    move-wide p2, v7

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    iget-boolean v4, p0, Lv01/f;->f:Z

    .line 21
    .line 22
    if-eqz v4, :cond_2

    .line 23
    .line 24
    sub-long v0, v2, v0

    .line 25
    .line 26
    cmp-long v4, v0, v7

    .line 27
    .line 28
    if-nez v4, :cond_1

    .line 29
    .line 30
    return-wide v5

    .line 31
    :cond_1
    invoke-static {p2, p3, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 32
    .line 33
    .line 34
    move-result-wide p2

    .line 35
    :cond_2
    :goto_0
    invoke-super {p0, p1, p2, p3}, Lu01/n;->A(Lu01/f;J)J

    .line 36
    .line 37
    .line 38
    move-result-wide p2

    .line 39
    cmp-long v0, p2, v5

    .line 40
    .line 41
    if-eqz v0, :cond_3

    .line 42
    .line 43
    iget-wide v4, p0, Lv01/f;->g:J

    .line 44
    .line 45
    add-long/2addr v4, p2

    .line 46
    iput-wide v4, p0, Lv01/f;->g:J

    .line 47
    .line 48
    :cond_3
    iget-wide v4, p0, Lv01/f;->g:J

    .line 49
    .line 50
    cmp-long v1, v4, v2

    .line 51
    .line 52
    if-gez v1, :cond_4

    .line 53
    .line 54
    if-eqz v0, :cond_5

    .line 55
    .line 56
    :cond_4
    if-lez v1, :cond_7

    .line 57
    .line 58
    :cond_5
    cmp-long p2, p2, v7

    .line 59
    .line 60
    if-lez p2, :cond_6

    .line 61
    .line 62
    if-lez v1, :cond_6

    .line 63
    .line 64
    iget-wide p2, p1, Lu01/f;->e:J

    .line 65
    .line 66
    sub-long/2addr v4, v2

    .line 67
    sub-long/2addr p2, v4

    .line 68
    new-instance v0, Lu01/f;

    .line 69
    .line 70
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 71
    .line 72
    .line 73
    invoke-virtual {v0, p1}, Lu01/f;->P(Lu01/h0;)J

    .line 74
    .line 75
    .line 76
    invoke-virtual {p1, v0, p2, p3}, Lu01/f;->F(Lu01/f;J)V

    .line 77
    .line 78
    .line 79
    invoke-virtual {v0}, Lu01/f;->a()V

    .line 80
    .line 81
    .line 82
    :cond_6
    new-instance p1, Ljava/io/IOException;

    .line 83
    .line 84
    const-string p2, "expected "

    .line 85
    .line 86
    const-string p3, " bytes but got "

    .line 87
    .line 88
    invoke-static {v2, v3, p2, p3}, Lp3/m;->o(JLjava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    move-result-object p2

    .line 92
    iget-wide v0, p0, Lv01/f;->g:J

    .line 93
    .line 94
    invoke-virtual {p2, v0, v1}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 95
    .line 96
    .line 97
    invoke-virtual {p2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 98
    .line 99
    .line 100
    move-result-object p0

    .line 101
    invoke-direct {p1, p0}, Ljava/io/IOException;-><init>(Ljava/lang/String;)V

    .line 102
    .line 103
    .line 104
    throw p1

    .line 105
    :cond_7
    return-wide p2
.end method
