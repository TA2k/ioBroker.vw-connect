.class public final Lh2/b1;
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

.field public final k:J

.field public final l:J


# direct methods
.method public constructor <init>(JJJJJJJJJJJJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lh2/b1;->a:J

    .line 5
    .line 6
    iput-wide p3, p0, Lh2/b1;->b:J

    .line 7
    .line 8
    iput-wide p5, p0, Lh2/b1;->c:J

    .line 9
    .line 10
    iput-wide p7, p0, Lh2/b1;->d:J

    .line 11
    .line 12
    iput-wide p9, p0, Lh2/b1;->e:J

    .line 13
    .line 14
    iput-wide p11, p0, Lh2/b1;->f:J

    .line 15
    .line 16
    iput-wide p13, p0, Lh2/b1;->g:J

    .line 17
    .line 18
    move-wide p1, p15

    .line 19
    iput-wide p1, p0, Lh2/b1;->h:J

    .line 20
    .line 21
    move-wide/from16 p1, p17

    .line 22
    .line 23
    iput-wide p1, p0, Lh2/b1;->i:J

    .line 24
    .line 25
    move-wide/from16 p1, p19

    .line 26
    .line 27
    iput-wide p1, p0, Lh2/b1;->j:J

    .line 28
    .line 29
    move-wide/from16 p1, p21

    .line 30
    .line 31
    iput-wide p1, p0, Lh2/b1;->k:J

    .line 32
    .line 33
    move-wide/from16 p1, p23

    .line 34
    .line 35
    iput-wide p1, p0, Lh2/b1;->l:J

    .line 36
    .line 37
    return-void
.end method

.method public static a(Lf4/a;Ll2/o;)Lc1/f1;
    .locals 2

    .line 1
    sget-object v0, Lf4/a;->e:Lf4/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    if-ne p0, v0, :cond_0

    .line 5
    .line 6
    check-cast p1, Ll2/t;

    .line 7
    .line 8
    const p0, 0x5bbf473f

    .line 9
    .line 10
    .line 11
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 12
    .line 13
    .line 14
    sget-object p0, Lk2/w;->g:Lk2/w;

    .line 15
    .line 16
    invoke-static {p0, p1}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 17
    .line 18
    .line 19
    move-result-object p0

    .line 20
    invoke-virtual {p1, v1}, Ll2/t;->q(Z)V

    .line 21
    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_0
    check-cast p1, Ll2/t;

    .line 25
    .line 26
    const p0, 0x5bc0b3bd

    .line 27
    .line 28
    .line 29
    invoke-virtual {p1, p0}, Ll2/t;->Y(I)V

    .line 30
    .line 31
    .line 32
    sget-object p0, Lk2/w;->f:Lk2/w;

    .line 33
    .line 34
    invoke-static {p0, p1}, Lh2/r;->C(Lk2/w;Ll2/o;)Lc1/f1;

    .line 35
    .line 36
    .line 37
    move-result-object p0

    .line 38
    invoke-virtual {p1, v1}, Ll2/t;->q(Z)V

    .line 39
    .line 40
    .line 41
    return-object p0
.end method


# virtual methods
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
    if-eqz p1, :cond_e

    .line 7
    .line 8
    instance-of v2, p1, Lh2/b1;

    .line 9
    .line 10
    if-nez v2, :cond_1

    .line 11
    .line 12
    goto/16 :goto_0

    .line 13
    .line 14
    :cond_1
    check-cast p1, Lh2/b1;

    .line 15
    .line 16
    iget-wide v2, p1, Lh2/b1;->a:J

    .line 17
    .line 18
    iget-wide v4, p0, Lh2/b1;->a:J

    .line 19
    .line 20
    invoke-static {v4, v5, v2, v3}, Le3/s;->c(JJ)Z

    .line 21
    .line 22
    .line 23
    move-result v2

    .line 24
    if-nez v2, :cond_2

    .line 25
    .line 26
    return v1

    .line 27
    :cond_2
    iget-wide v2, p0, Lh2/b1;->b:J

    .line 28
    .line 29
    iget-wide v4, p1, Lh2/b1;->b:J

    .line 30
    .line 31
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 32
    .line 33
    .line 34
    move-result v2

    .line 35
    if-nez v2, :cond_3

    .line 36
    .line 37
    return v1

    .line 38
    :cond_3
    iget-wide v2, p0, Lh2/b1;->c:J

    .line 39
    .line 40
    iget-wide v4, p1, Lh2/b1;->c:J

    .line 41
    .line 42
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 43
    .line 44
    .line 45
    move-result v2

    .line 46
    if-nez v2, :cond_4

    .line 47
    .line 48
    return v1

    .line 49
    :cond_4
    iget-wide v2, p0, Lh2/b1;->d:J

    .line 50
    .line 51
    iget-wide v4, p1, Lh2/b1;->d:J

    .line 52
    .line 53
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 54
    .line 55
    .line 56
    move-result v2

    .line 57
    if-nez v2, :cond_5

    .line 58
    .line 59
    return v1

    .line 60
    :cond_5
    iget-wide v2, p0, Lh2/b1;->e:J

    .line 61
    .line 62
    iget-wide v4, p1, Lh2/b1;->e:J

    .line 63
    .line 64
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 65
    .line 66
    .line 67
    move-result v2

    .line 68
    if-nez v2, :cond_6

    .line 69
    .line 70
    return v1

    .line 71
    :cond_6
    iget-wide v2, p0, Lh2/b1;->f:J

    .line 72
    .line 73
    iget-wide v4, p1, Lh2/b1;->f:J

    .line 74
    .line 75
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 76
    .line 77
    .line 78
    move-result v2

    .line 79
    if-nez v2, :cond_7

    .line 80
    .line 81
    return v1

    .line 82
    :cond_7
    iget-wide v2, p0, Lh2/b1;->g:J

    .line 83
    .line 84
    iget-wide v4, p1, Lh2/b1;->g:J

    .line 85
    .line 86
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 87
    .line 88
    .line 89
    move-result v2

    .line 90
    if-nez v2, :cond_8

    .line 91
    .line 92
    return v1

    .line 93
    :cond_8
    iget-wide v2, p0, Lh2/b1;->h:J

    .line 94
    .line 95
    iget-wide v4, p1, Lh2/b1;->h:J

    .line 96
    .line 97
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 98
    .line 99
    .line 100
    move-result v2

    .line 101
    if-nez v2, :cond_9

    .line 102
    .line 103
    return v1

    .line 104
    :cond_9
    iget-wide v2, p0, Lh2/b1;->i:J

    .line 105
    .line 106
    iget-wide v4, p1, Lh2/b1;->i:J

    .line 107
    .line 108
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 109
    .line 110
    .line 111
    move-result v2

    .line 112
    if-nez v2, :cond_a

    .line 113
    .line 114
    return v1

    .line 115
    :cond_a
    iget-wide v2, p0, Lh2/b1;->j:J

    .line 116
    .line 117
    iget-wide v4, p1, Lh2/b1;->j:J

    .line 118
    .line 119
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 120
    .line 121
    .line 122
    move-result v2

    .line 123
    if-nez v2, :cond_b

    .line 124
    .line 125
    return v1

    .line 126
    :cond_b
    iget-wide v2, p0, Lh2/b1;->k:J

    .line 127
    .line 128
    iget-wide v4, p1, Lh2/b1;->k:J

    .line 129
    .line 130
    invoke-static {v2, v3, v4, v5}, Le3/s;->c(JJ)Z

    .line 131
    .line 132
    .line 133
    move-result v2

    .line 134
    if-nez v2, :cond_c

    .line 135
    .line 136
    return v1

    .line 137
    :cond_c
    iget-wide v2, p0, Lh2/b1;->l:J

    .line 138
    .line 139
    iget-wide p0, p1, Lh2/b1;->l:J

    .line 140
    .line 141
    invoke-static {v2, v3, p0, p1}, Le3/s;->c(JJ)Z

    .line 142
    .line 143
    .line 144
    move-result p0

    .line 145
    if-nez p0, :cond_d

    .line 146
    .line 147
    return v1

    .line 148
    :cond_d
    return v0

    .line 149
    :cond_e
    :goto_0
    return v1
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    sget v0, Le3/s;->j:I

    .line 2
    .line 3
    iget-wide v0, p0, Lh2/b1;->a:J

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
    iget-wide v2, p0, Lh2/b1;->b:J

    .line 13
    .line 14
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 15
    .line 16
    .line 17
    move-result v0

    .line 18
    iget-wide v2, p0, Lh2/b1;->c:J

    .line 19
    .line 20
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-wide v2, p0, Lh2/b1;->d:J

    .line 25
    .line 26
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 27
    .line 28
    .line 29
    move-result v0

    .line 30
    iget-wide v2, p0, Lh2/b1;->e:J

    .line 31
    .line 32
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    iget-wide v2, p0, Lh2/b1;->f:J

    .line 37
    .line 38
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 39
    .line 40
    .line 41
    move-result v0

    .line 42
    iget-wide v2, p0, Lh2/b1;->g:J

    .line 43
    .line 44
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 45
    .line 46
    .line 47
    move-result v0

    .line 48
    iget-wide v2, p0, Lh2/b1;->h:J

    .line 49
    .line 50
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    iget-wide v2, p0, Lh2/b1;->i:J

    .line 55
    .line 56
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    iget-wide v2, p0, Lh2/b1;->j:J

    .line 61
    .line 62
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 63
    .line 64
    .line 65
    move-result v0

    .line 66
    iget-wide v2, p0, Lh2/b1;->k:J

    .line 67
    .line 68
    invoke-static {v2, v3, v0, v1}, La7/g0;->f(JII)I

    .line 69
    .line 70
    .line 71
    move-result v0

    .line 72
    iget-wide v1, p0, Lh2/b1;->l:J

    .line 73
    .line 74
    invoke-static {v1, v2}, Ljava/lang/Long;->hashCode(J)I

    .line 75
    .line 76
    .line 77
    move-result p0

    .line 78
    add-int/2addr p0, v0

    .line 79
    return p0
.end method
