.class public final Lu01/z;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lu01/h0;


# instance fields
.field public final d:Lu01/h;

.field public final e:Lu01/f;

.field public f:Lu01/c0;

.field public g:I

.field public h:Z

.field public i:J


# direct methods
.method public constructor <init>(Lu01/h;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lu01/z;->d:Lu01/h;

    .line 5
    .line 6
    invoke-interface {p1}, Lu01/h;->n()Lu01/f;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    iput-object p1, p0, Lu01/z;->e:Lu01/f;

    .line 11
    .line 12
    iget-object p1, p1, Lu01/f;->d:Lu01/c0;

    .line 13
    .line 14
    iput-object p1, p0, Lu01/z;->f:Lu01/c0;

    .line 15
    .line 16
    if-eqz p1, :cond_0

    .line 17
    .line 18
    iget p1, p1, Lu01/c0;->b:I

    .line 19
    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const/4 p1, -0x1

    .line 22
    :goto_0
    iput p1, p0, Lu01/z;->g:I

    .line 23
    .line 24
    return-void
.end method


# virtual methods
.method public final A(Lu01/f;J)J
    .locals 8

    .line 1
    const-string v0, "sink"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-wide/16 v0, 0x0

    .line 7
    .line 8
    cmp-long v2, p2, v0

    .line 9
    .line 10
    if-ltz v2, :cond_6

    .line 11
    .line 12
    iget-boolean v3, p0, Lu01/z;->h:Z

    .line 13
    .line 14
    if-nez v3, :cond_5

    .line 15
    .line 16
    iget-object v3, p0, Lu01/z;->f:Lu01/c0;

    .line 17
    .line 18
    iget-object v4, p0, Lu01/z;->e:Lu01/f;

    .line 19
    .line 20
    if-eqz v3, :cond_1

    .line 21
    .line 22
    iget-object v5, v4, Lu01/f;->d:Lu01/c0;

    .line 23
    .line 24
    if-ne v3, v5, :cond_0

    .line 25
    .line 26
    iget v3, p0, Lu01/z;->g:I

    .line 27
    .line 28
    invoke-static {v5}, Lkotlin/jvm/internal/m;->c(Ljava/lang/Object;)V

    .line 29
    .line 30
    .line 31
    iget v5, v5, Lu01/c0;->b:I

    .line 32
    .line 33
    if-ne v3, v5, :cond_0

    .line 34
    .line 35
    goto :goto_0

    .line 36
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 37
    .line 38
    const-string p1, "Peek source is invalid because upstream source was used"

    .line 39
    .line 40
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 41
    .line 42
    .line 43
    throw p0

    .line 44
    :cond_1
    :goto_0
    if-nez v2, :cond_2

    .line 45
    .line 46
    return-wide v0

    .line 47
    :cond_2
    iget-wide v0, p0, Lu01/z;->i:J

    .line 48
    .line 49
    const-wide/16 v2, 0x1

    .line 50
    .line 51
    add-long/2addr v0, v2

    .line 52
    iget-object v2, p0, Lu01/z;->d:Lu01/h;

    .line 53
    .line 54
    invoke-interface {v2, v0, v1}, Lu01/h;->c(J)Z

    .line 55
    .line 56
    .line 57
    move-result v0

    .line 58
    if-nez v0, :cond_3

    .line 59
    .line 60
    const-wide/16 p0, -0x1

    .line 61
    .line 62
    return-wide p0

    .line 63
    :cond_3
    iget-object v0, p0, Lu01/z;->f:Lu01/c0;

    .line 64
    .line 65
    if-nez v0, :cond_4

    .line 66
    .line 67
    iget-object v0, v4, Lu01/f;->d:Lu01/c0;

    .line 68
    .line 69
    if-eqz v0, :cond_4

    .line 70
    .line 71
    iput-object v0, p0, Lu01/z;->f:Lu01/c0;

    .line 72
    .line 73
    iget v0, v0, Lu01/c0;->b:I

    .line 74
    .line 75
    iput v0, p0, Lu01/z;->g:I

    .line 76
    .line 77
    :cond_4
    iget-wide v0, v4, Lu01/f;->e:J

    .line 78
    .line 79
    iget-wide v2, p0, Lu01/z;->i:J

    .line 80
    .line 81
    sub-long/2addr v0, v2

    .line 82
    invoke-static {p2, p3, v0, v1}, Ljava/lang/Math;->min(JJ)J

    .line 83
    .line 84
    .line 85
    move-result-wide v6

    .line 86
    iget-object v2, p0, Lu01/z;->e:Lu01/f;

    .line 87
    .line 88
    iget-wide v4, p0, Lu01/z;->i:J

    .line 89
    .line 90
    move-object v3, p1

    .line 91
    invoke-virtual/range {v2 .. v7}, Lu01/f;->f(Lu01/f;JJ)V

    .line 92
    .line 93
    .line 94
    iget-wide p1, p0, Lu01/z;->i:J

    .line 95
    .line 96
    add-long/2addr p1, v6

    .line 97
    iput-wide p1, p0, Lu01/z;->i:J

    .line 98
    .line 99
    return-wide v6

    .line 100
    :cond_5
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 101
    .line 102
    const-string p1, "closed"

    .line 103
    .line 104
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 105
    .line 106
    .line 107
    throw p0

    .line 108
    :cond_6
    const-string p0, "byteCount < 0: "

    .line 109
    .line 110
    invoke-static {p2, p3, p0}, Lp3/m;->f(JLjava/lang/String;)Ljava/lang/String;

    .line 111
    .line 112
    .line 113
    move-result-object p0

    .line 114
    new-instance p1, Ljava/lang/IllegalArgumentException;

    .line 115
    .line 116
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 117
    .line 118
    .line 119
    move-result-object p0

    .line 120
    invoke-direct {p1, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 121
    .line 122
    .line 123
    throw p1
.end method

.method public final close()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lu01/z;->h:Z

    .line 3
    .line 4
    return-void
.end method

.method public final timeout()Lu01/j0;
    .locals 0

    .line 1
    iget-object p0, p0, Lu01/z;->d:Lu01/h;

    .line 2
    .line 3
    invoke-interface {p0}, Lu01/h0;->timeout()Lu01/j0;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
