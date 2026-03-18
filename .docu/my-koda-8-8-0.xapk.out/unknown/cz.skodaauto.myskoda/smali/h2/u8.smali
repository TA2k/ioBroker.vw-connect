.class public final Lh2/u8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:J

.field public final b:J

.field public final c:J

.field public final d:J

.field public final e:J

.field public final f:J

.field public final g:J

.field public final h:J

.field public final i:J

.field public final j:J


# direct methods
.method public constructor <init>(JJJJJJJJJJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lh2/u8;->a:J

    .line 5
    .line 6
    iput-wide p3, p0, Lh2/u8;->b:J

    .line 7
    .line 8
    iput-wide p5, p0, Lh2/u8;->c:J

    .line 9
    .line 10
    iput-wide p7, p0, Lh2/u8;->d:J

    .line 11
    .line 12
    iput-wide p9, p0, Lh2/u8;->e:J

    .line 13
    .line 14
    iput-wide p11, p0, Lh2/u8;->f:J

    .line 15
    .line 16
    iput-wide p13, p0, Lh2/u8;->g:J

    .line 17
    .line 18
    move-wide p1, p15

    .line 19
    iput-wide p1, p0, Lh2/u8;->h:J

    .line 20
    .line 21
    move-wide/from16 p1, p17

    .line 22
    .line 23
    iput-wide p1, p0, Lh2/u8;->i:J

    .line 24
    .line 25
    move-wide/from16 p1, p19

    .line 26
    .line 27
    iput-wide p1, p0, Lh2/u8;->j:J

    .line 28
    .line 29
    return-void
.end method


# virtual methods
.method public final a(ZZ)J
    .locals 0

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget-wide p0, p0, Lh2/u8;->c:J

    .line 6
    .line 7
    return-wide p0

    .line 8
    :cond_0
    iget-wide p0, p0, Lh2/u8;->e:J

    .line 9
    .line 10
    return-wide p0

    .line 11
    :cond_1
    if-eqz p2, :cond_2

    .line 12
    .line 13
    iget-wide p0, p0, Lh2/u8;->h:J

    .line 14
    .line 15
    return-wide p0

    .line 16
    :cond_2
    iget-wide p0, p0, Lh2/u8;->j:J

    .line 17
    .line 18
    return-wide p0
.end method

.method public final b(ZZ)J
    .locals 0

    .line 1
    if-eqz p1, :cond_1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget-wide p0, p0, Lh2/u8;->b:J

    .line 6
    .line 7
    return-wide p0

    .line 8
    :cond_0
    iget-wide p0, p0, Lh2/u8;->d:J

    .line 9
    .line 10
    return-wide p0

    .line 11
    :cond_1
    if-eqz p2, :cond_2

    .line 12
    .line 13
    iget-wide p0, p0, Lh2/u8;->g:J

    .line 14
    .line 15
    return-wide p0

    .line 16
    :cond_2
    iget-wide p0, p0, Lh2/u8;->i:J

    .line 17
    .line 18
    return-wide p0
.end method

.method public final equals(Ljava/lang/Object;)Z
    .locals 6

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    const/4 v1, 0x0

    .line 6
    if-eqz p1, :cond_c

    .line 7
    .line 8
    instance-of v2, p1, Lh2/u8;

    .line 9
    .line 10
    if-nez v2, :cond_1

    .line 11
    .line 12
    goto :goto_0

    .line 13
    :cond_1
    check-cast p1, Lh2/u8;

    .line 14
    .line 15
    iget-wide v2, p1, Lh2/u8;->a:J

    .line 16
    .line 17
    iget-wide v4, p0, Lh2/u8;->a:J

    .line 18
    .line 19
    invoke-static {v4, v5, v2, v3}, Le3/s;->c(JJ)Z

    .line 20
    .line 21
    .line 22
    move-result v2

    .line 23
    if-nez v2, :cond_2

    .line 24
    .line 25
    return v1

    .line 26
    :cond_2
    iget-wide v2, p0, Lh2/u8;->b:J

    .line 27
    .line 28
    iget-wide v4, p1, Lh2/u8;->b:J

    .line 29
    .line 30
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 31
    .line 32
    .line 33
    move-result v2

    .line 34
    if-nez v2, :cond_3

    .line 35
    .line 36
    return v1

    .line 37
    :cond_3
    iget-wide v2, p0, Lh2/u8;->c:J

    .line 38
    .line 39
    iget-wide v4, p1, Lh2/u8;->c:J

    .line 40
    .line 41
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 42
    .line 43
    .line 44
    move-result v2

    .line 45
    if-nez v2, :cond_4

    .line 46
    .line 47
    return v1

    .line 48
    :cond_4
    iget-wide v2, p0, Lh2/u8;->d:J

    .line 49
    .line 50
    iget-wide v4, p1, Lh2/u8;->d:J

    .line 51
    .line 52
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 53
    .line 54
    .line 55
    move-result v2

    .line 56
    if-nez v2, :cond_5

    .line 57
    .line 58
    return v1

    .line 59
    :cond_5
    iget-wide v2, p0, Lh2/u8;->e:J

    .line 60
    .line 61
    iget-wide v4, p1, Lh2/u8;->e:J

    .line 62
    .line 63
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 64
    .line 65
    .line 66
    move-result v2

    .line 67
    if-nez v2, :cond_6

    .line 68
    .line 69
    return v1

    .line 70
    :cond_6
    iget-wide v2, p0, Lh2/u8;->f:J

    .line 71
    .line 72
    iget-wide v4, p1, Lh2/u8;->f:J

    .line 73
    .line 74
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 75
    .line 76
    .line 77
    move-result v2

    .line 78
    if-nez v2, :cond_7

    .line 79
    .line 80
    return v1

    .line 81
    :cond_7
    iget-wide v2, p0, Lh2/u8;->g:J

    .line 82
    .line 83
    iget-wide v4, p1, Lh2/u8;->g:J

    .line 84
    .line 85
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 86
    .line 87
    .line 88
    move-result v2

    .line 89
    if-nez v2, :cond_8

    .line 90
    .line 91
    return v1

    .line 92
    :cond_8
    iget-wide v2, p0, Lh2/u8;->h:J

    .line 93
    .line 94
    iget-wide v4, p1, Lh2/u8;->h:J

    .line 95
    .line 96
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 97
    .line 98
    .line 99
    move-result v2

    .line 100
    if-nez v2, :cond_9

    .line 101
    .line 102
    return v1

    .line 103
    :cond_9
    iget-wide v2, p0, Lh2/u8;->i:J

    .line 104
    .line 105
    iget-wide v4, p1, Lh2/u8;->i:J

    .line 106
    .line 107
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 108
    .line 109
    .line 110
    move-result v2

    .line 111
    if-nez v2, :cond_a

    .line 112
    .line 113
    return v1

    .line 114
    :cond_a
    iget-wide v2, p0, Lh2/u8;->j:J

    .line 115
    .line 116
    iget-wide p0, p1, Lh2/u8;->j:J

    .line 117
    .line 118
    invoke-static {v2, v3, p0, p1}, Le3/s;->c(JJ)Z

    .line 119
    .line 120
    .line 121
    move-result p0

    .line 122
    if-nez p0, :cond_b

    .line 123
    .line 124
    return v1

    .line 125
    :cond_b
    return v0

    .line 126
    :cond_c
    :goto_0
    return v1
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    sget v0, Le3/s;->j:I

    .line 2
    .line 3
    iget-wide v0, p0, Lh2/u8;->a:J

    .line 4
    .line 5
    invoke-static {v0, v1}, Ljava/lang/Long;->hashCode(J)I

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    const/16 v1, 0x1f

    .line 10
    .line 11
    mul-int/2addr v0, v1

    .line 12
    iget-wide v2, p0, Lh2/u8;->b:J

    .line 13
    .line 14
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    iget-wide v2, p0, Lh2/u8;->c:J

    .line 19
    .line 20
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-wide v2, p0, Lh2/u8;->d:J

    .line 25
    .line 26
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget-wide v2, p0, Lh2/u8;->e:J

    .line 31
    .line 32
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-wide v2, p0, Lh2/u8;->f:J

    .line 37
    .line 38
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget-wide v2, p0, Lh2/u8;->g:J

    .line 43
    .line 44
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iget-wide v2, p0, Lh2/u8;->h:J

    .line 49
    .line 50
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-wide v2, p0, Lh2/u8;->i:J

    .line 55
    .line 56
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    iget-wide v1, p0, Lh2/u8;->j:J

    .line 61
    .line 62
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 63
    .line 64
    .line 65
    move-result p0

    .line 66
    add-int/2addr p0, v0

    .line 67
    return p0
.end method
