.class public final Lj9/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:I

.field public b:J

.field public c:I

.field public d:I

.field public e:I

.field public final f:[I

.field public final g:Lw7/p;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/16 v0, 0xff

    .line 5
    .line 6
    new-array v1, v0, [I

    .line 7
    .line 8
    iput-object v1, p0, Lj9/g;->f:[I

    .line 9
    .line 10
    new-instance v1, Lw7/p;

    .line 11
    .line 12
    invoke-direct {v1, v0}, Lw7/p;-><init>(I)V

    .line 13
    .line 14
    .line 15
    iput-object v1, p0, Lj9/g;->g:Lw7/p;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a(Lo8/p;Z)Z
    .locals 6

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Lj9/g;->a:I

    .line 3
    .line 4
    const-wide/16 v1, 0x0

    .line 5
    .line 6
    iput-wide v1, p0, Lj9/g;->b:J

    .line 7
    .line 8
    iput v0, p0, Lj9/g;->c:I

    .line 9
    .line 10
    iput v0, p0, Lj9/g;->d:I

    .line 11
    .line 12
    iput v0, p0, Lj9/g;->e:I

    .line 13
    .line 14
    iget-object v1, p0, Lj9/g;->g:Lw7/p;

    .line 15
    .line 16
    const/16 v2, 0x1b

    .line 17
    .line 18
    invoke-virtual {v1, v2}, Lw7/p;->F(I)V

    .line 19
    .line 20
    .line 21
    iget-object v3, v1, Lw7/p;->a:[B

    .line 22
    .line 23
    :try_start_0
    invoke-interface {p1, v3, v0, v2, p2}, Lo8/p;->b([BIIZ)Z

    .line 24
    .line 25
    .line 26
    move-result v2
    :try_end_0
    .catch Ljava/io/EOFException; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    goto :goto_0

    .line 28
    :catch_0
    move-exception v2

    .line 29
    if-eqz p2, :cond_7

    .line 30
    .line 31
    move v2, v0

    .line 32
    :goto_0
    if-eqz v2, :cond_6

    .line 33
    .line 34
    invoke-virtual {v1}, Lw7/p;->y()J

    .line 35
    .line 36
    .line 37
    move-result-wide v2

    .line 38
    const-wide/32 v4, 0x4f676753

    .line 39
    .line 40
    .line 41
    cmp-long v2, v2, v4

    .line 42
    .line 43
    if-eqz v2, :cond_0

    .line 44
    .line 45
    goto :goto_3

    .line 46
    :cond_0
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 47
    .line 48
    .line 49
    move-result v2

    .line 50
    if-eqz v2, :cond_2

    .line 51
    .line 52
    if-eqz p2, :cond_1

    .line 53
    .line 54
    goto :goto_3

    .line 55
    :cond_1
    const-string p0, "unsupported bit stream revision"

    .line 56
    .line 57
    invoke-static {p0}, Lt7/e0;->b(Ljava/lang/String;)Lt7/e0;

    .line 58
    .line 59
    .line 60
    move-result-object p0

    .line 61
    throw p0

    .line 62
    :cond_2
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 63
    .line 64
    .line 65
    move-result v2

    .line 66
    iput v2, p0, Lj9/g;->a:I

    .line 67
    .line 68
    invoke-virtual {v1}, Lw7/p;->m()J

    .line 69
    .line 70
    .line 71
    move-result-wide v2

    .line 72
    iput-wide v2, p0, Lj9/g;->b:J

    .line 73
    .line 74
    invoke-virtual {v1}, Lw7/p;->n()J

    .line 75
    .line 76
    .line 77
    invoke-virtual {v1}, Lw7/p;->n()J

    .line 78
    .line 79
    .line 80
    invoke-virtual {v1}, Lw7/p;->n()J

    .line 81
    .line 82
    .line 83
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 84
    .line 85
    .line 86
    move-result v2

    .line 87
    iput v2, p0, Lj9/g;->c:I

    .line 88
    .line 89
    add-int/lit8 v3, v2, 0x1b

    .line 90
    .line 91
    iput v3, p0, Lj9/g;->d:I

    .line 92
    .line 93
    invoke-virtual {v1, v2}, Lw7/p;->F(I)V

    .line 94
    .line 95
    .line 96
    iget-object v2, v1, Lw7/p;->a:[B

    .line 97
    .line 98
    iget v3, p0, Lj9/g;->c:I

    .line 99
    .line 100
    :try_start_1
    invoke-interface {p1, v2, v0, v3, p2}, Lo8/p;->b([BIIZ)Z

    .line 101
    .line 102
    .line 103
    move-result p1
    :try_end_1
    .catch Ljava/io/EOFException; {:try_start_1 .. :try_end_1} :catch_1

    .line 104
    goto :goto_1

    .line 105
    :catch_1
    move-exception p1

    .line 106
    if-eqz p2, :cond_5

    .line 107
    .line 108
    move p1, v0

    .line 109
    :goto_1
    if-nez p1, :cond_3

    .line 110
    .line 111
    goto :goto_3

    .line 112
    :cond_3
    :goto_2
    iget p1, p0, Lj9/g;->c:I

    .line 113
    .line 114
    if-ge v0, p1, :cond_4

    .line 115
    .line 116
    invoke-virtual {v1}, Lw7/p;->w()I

    .line 117
    .line 118
    .line 119
    move-result p1

    .line 120
    iget-object p2, p0, Lj9/g;->f:[I

    .line 121
    .line 122
    aput p1, p2, v0

    .line 123
    .line 124
    iget p2, p0, Lj9/g;->e:I

    .line 125
    .line 126
    add-int/2addr p2, p1

    .line 127
    iput p2, p0, Lj9/g;->e:I

    .line 128
    .line 129
    add-int/lit8 v0, v0, 0x1

    .line 130
    .line 131
    goto :goto_2

    .line 132
    :cond_4
    const/4 p0, 0x1

    .line 133
    return p0

    .line 134
    :cond_5
    throw p1

    .line 135
    :cond_6
    :goto_3
    return v0

    .line 136
    :cond_7
    throw v2
.end method

.method public final b(Lo8/p;J)Z
    .locals 8

    .line 1
    invoke-interface {p1}, Lo8/p;->getPosition()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-interface {p1}, Lo8/p;->h()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    cmp-long v0, v0, v2

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    const/4 v2, 0x1

    .line 13
    if-nez v0, :cond_0

    .line 14
    .line 15
    move v0, v2

    .line 16
    goto :goto_0

    .line 17
    :cond_0
    move v0, v1

    .line 18
    :goto_0
    invoke-static {v0}, Lw7/a;->c(Z)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Lj9/g;->g:Lw7/p;

    .line 22
    .line 23
    const/4 v0, 0x4

    .line 24
    invoke-virtual {p0, v0}, Lw7/p;->F(I)V

    .line 25
    .line 26
    .line 27
    :goto_1
    const-wide/16 v3, -0x1

    .line 28
    .line 29
    cmp-long v3, p2, v3

    .line 30
    .line 31
    if-eqz v3, :cond_1

    .line 32
    .line 33
    invoke-interface {p1}, Lo8/p;->getPosition()J

    .line 34
    .line 35
    .line 36
    move-result-wide v4

    .line 37
    const-wide/16 v6, 0x4

    .line 38
    .line 39
    add-long/2addr v4, v6

    .line 40
    cmp-long v4, v4, p2

    .line 41
    .line 42
    if-gez v4, :cond_3

    .line 43
    .line 44
    :cond_1
    iget-object v4, p0, Lw7/p;->a:[B

    .line 45
    .line 46
    :try_start_0
    invoke-interface {p1, v4, v1, v0, v2}, Lo8/p;->b([BIIZ)Z

    .line 47
    .line 48
    .line 49
    move-result v4
    :try_end_0
    .catch Ljava/io/EOFException; {:try_start_0 .. :try_end_0} :catch_0

    .line 50
    goto :goto_2

    .line 51
    :catch_0
    move v4, v1

    .line 52
    :goto_2
    if-eqz v4, :cond_3

    .line 53
    .line 54
    invoke-virtual {p0, v1}, Lw7/p;->I(I)V

    .line 55
    .line 56
    .line 57
    invoke-virtual {p0}, Lw7/p;->y()J

    .line 58
    .line 59
    .line 60
    move-result-wide v3

    .line 61
    const-wide/32 v5, 0x4f676753

    .line 62
    .line 63
    .line 64
    cmp-long v3, v3, v5

    .line 65
    .line 66
    if-nez v3, :cond_2

    .line 67
    .line 68
    invoke-interface {p1}, Lo8/p;->e()V

    .line 69
    .line 70
    .line 71
    return v2

    .line 72
    :cond_2
    invoke-interface {p1, v2}, Lo8/p;->n(I)V

    .line 73
    .line 74
    .line 75
    goto :goto_1

    .line 76
    :cond_3
    :goto_3
    if-eqz v3, :cond_4

    .line 77
    .line 78
    invoke-interface {p1}, Lo8/p;->getPosition()J

    .line 79
    .line 80
    .line 81
    move-result-wide v4

    .line 82
    cmp-long p0, v4, p2

    .line 83
    .line 84
    if-gez p0, :cond_5

    .line 85
    .line 86
    :cond_4
    invoke-interface {p1, v2}, Lo8/p;->j(I)I

    .line 87
    .line 88
    .line 89
    move-result p0

    .line 90
    const/4 v0, -0x1

    .line 91
    if-eq p0, v0, :cond_5

    .line 92
    .line 93
    goto :goto_3

    .line 94
    :cond_5
    return v1
.end method
