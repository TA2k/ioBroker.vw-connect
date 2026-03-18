.class public final Lp11/h;
.super Lq11/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic h:I

.field public final i:Lp11/m;


# direct methods
.method public constructor <init>(Lp11/m;I)V
    .locals 2

    .line 1
    iput p2, p0, Lp11/h;->h:I

    .line 2
    .line 3
    packed-switch p2, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p2, Ln11/b;->q:Ln11/b;

    .line 7
    .line 8
    const-wide v0, 0x758f0dfc0L

    .line 9
    .line 10
    .line 11
    .line 12
    .line 13
    invoke-direct {p0, p2, v0, v1}, Lq11/f;-><init>(Ln11/b;J)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lp11/h;->i:Lp11/m;

    .line 17
    .line 18
    return-void

    .line 19
    :pswitch_0
    sget-object p2, Ln11/b;->l:Ln11/b;

    .line 20
    .line 21
    const-wide v0, 0x758f0dfc0L

    .line 22
    .line 23
    .line 24
    .line 25
    .line 26
    invoke-direct {p0, p2, v0, v1}, Lq11/f;-><init>(Ln11/b;J)V

    .line 27
    .line 28
    .line 29
    iput-object p1, p0, Lp11/h;->i:Lp11/m;

    .line 30
    .line 31
    return-void

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final a(IJ)J
    .locals 3

    .line 1
    iget v0, p0, Lp11/h;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    if-nez p1, :cond_0

    .line 7
    .line 8
    goto :goto_1

    .line 9
    :cond_0
    iget-object v0, p0, Lp11/h;->i:Lp11/m;

    .line 10
    .line 11
    invoke-virtual {v0, p2, p3}, Lp11/e;->X(J)I

    .line 12
    .line 13
    .line 14
    move-result v0

    .line 15
    add-int v1, v0, p1

    .line 16
    .line 17
    xor-int v2, v0, v1

    .line 18
    .line 19
    if-gez v2, :cond_2

    .line 20
    .line 21
    xor-int v2, v0, p1

    .line 22
    .line 23
    if-gez v2, :cond_1

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_1
    new-instance p0, Ljava/lang/ArithmeticException;

    .line 27
    .line 28
    const-string p2, "The calculation caused an overflow: "

    .line 29
    .line 30
    const-string p3, " + "

    .line 31
    .line 32
    invoke-static {p2, p3, v0, p1}, Lp3/m;->i(Ljava/lang/String;Ljava/lang/String;II)Ljava/lang/String;

    .line 33
    .line 34
    .line 35
    move-result-object p1

    .line 36
    invoke-direct {p0, p1}, Ljava/lang/ArithmeticException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :cond_2
    :goto_0
    invoke-virtual {p0, v1, p2, p3}, Lp11/h;->v(IJ)J

    .line 41
    .line 42
    .line 43
    move-result-wide p2

    .line 44
    :goto_1
    return-wide p2

    .line 45
    :pswitch_0
    if-nez p1, :cond_3

    .line 46
    .line 47
    goto :goto_2

    .line 48
    :cond_3
    iget-object v0, p0, Lp11/h;->i:Lp11/m;

    .line 49
    .line 50
    invoke-virtual {v0, p2, p3}, Lp11/e;->W(J)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    add-int/2addr v0, p1

    .line 55
    invoke-virtual {p0, v0, p2, p3}, Lp11/h;->v(IJ)J

    .line 56
    .line 57
    .line 58
    move-result-wide p2

    .line 59
    :goto_2
    return-wide p2

    .line 60
    nop

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final b(J)I
    .locals 1

    .line 1
    iget v0, p0, Lp11/h;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lp11/h;->i:Lp11/m;

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2}, Lp11/e;->X(J)I

    .line 9
    .line 10
    .line 11
    move-result p0

    .line 12
    return p0

    .line 13
    :pswitch_0
    iget-object p0, p0, Lp11/h;->i:Lp11/m;

    .line 14
    .line 15
    invoke-virtual {p0, p1, p2}, Lp11/e;->W(J)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final j()Ln11/g;
    .locals 1

    .line 1
    iget v0, p0, Lp11/h;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lp11/h;->i:Lp11/m;

    .line 7
    .line 8
    iget-object p0, p0, Lp11/b;->k:Ln11/g;

    .line 9
    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lp11/h;->i:Lp11/m;

    .line 12
    .line 13
    iget-object p0, p0, Lp11/b;->l:Ln11/g;

    .line 14
    .line 15
    return-object p0

    .line 16
    nop

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final l()I
    .locals 1

    .line 1
    iget v0, p0, Lp11/h;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lp11/h;->i:Lp11/m;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    :goto_0
    const p0, 0x116bd2d1

    .line 12
    .line 13
    .line 14
    return p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lp11/h;->i:Lp11/m;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    goto :goto_0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final o()I
    .locals 1

    .line 1
    iget v0, p0, Lp11/h;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lp11/h;->i:Lp11/m;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    :goto_0
    const p0, -0x116bc36e

    .line 12
    .line 13
    .line 14
    return p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lp11/h;->i:Lp11/m;

    .line 16
    .line 17
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 18
    .line 19
    .line 20
    goto :goto_0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final p()Ln11/g;
    .locals 0

    .line 1
    iget p0, p0, Lp11/h;->h:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x0

    .line 7
    return-object p0

    .line 8
    :pswitch_0
    const/4 p0, 0x0

    .line 9
    return-object p0

    .line 10
    nop

    .line 11
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final r(J)Z
    .locals 1

    .line 1
    iget v0, p0, Lp11/h;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lp11/h;->i:Lp11/m;

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2}, Lp11/e;->X(J)I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    invoke-virtual {p0, p1}, Lp11/m;->a0(I)Z

    .line 13
    .line 14
    .line 15
    move-result p0

    .line 16
    return p0

    .line 17
    :pswitch_0
    iget-object p0, p0, Lp11/h;->i:Lp11/m;

    .line 18
    .line 19
    invoke-virtual {p0, p1, p2}, Lp11/e;->W(J)I

    .line 20
    .line 21
    .line 22
    move-result p1

    .line 23
    invoke-virtual {p0, p1}, Lp11/e;->V(I)I

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    const/16 p1, 0x34

    .line 28
    .line 29
    if-le p0, p1, :cond_0

    .line 30
    .line 31
    const/4 p0, 0x1

    .line 32
    goto :goto_0

    .line 33
    :cond_0
    const/4 p0, 0x0

    .line 34
    :goto_0
    return p0

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final t(J)J
    .locals 2

    .line 1
    iget v0, p0, Lp11/h;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-virtual {p0, p1, p2}, Lp11/h;->u(J)J

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    :goto_0
    sub-long/2addr p1, v0

    .line 11
    return-wide p1

    .line 12
    :pswitch_0
    invoke-virtual {p0, p1, p2}, Lp11/h;->u(J)J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    goto :goto_0

    .line 17
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final u(J)J
    .locals 4

    .line 1
    iget v0, p0, Lp11/h;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lp11/h;->i:Lp11/m;

    .line 7
    .line 8
    invoke-virtual {p0, p1, p2}, Lp11/e;->X(J)I

    .line 9
    .line 10
    .line 11
    move-result p1

    .line 12
    invoke-virtual {p0, p1}, Lp11/e;->Y(I)J

    .line 13
    .line 14
    .line 15
    move-result-wide p0

    .line 16
    return-wide p0

    .line 17
    :pswitch_0
    iget-object p0, p0, Lp11/h;->i:Lp11/m;

    .line 18
    .line 19
    iget-object v0, p0, Lp11/b;->F:Ln11/a;

    .line 20
    .line 21
    invoke-virtual {v0, p1, p2}, Ln11/a;->u(J)J

    .line 22
    .line 23
    .line 24
    move-result-wide p1

    .line 25
    invoke-virtual {p0, p1, p2}, Lp11/e;->X(J)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    invoke-virtual {p0, v0, p1, p2}, Lp11/e;->U(IJ)I

    .line 30
    .line 31
    .line 32
    move-result p0

    .line 33
    const/4 v0, 0x1

    .line 34
    if-le p0, v0, :cond_0

    .line 35
    .line 36
    sub-int/2addr p0, v0

    .line 37
    int-to-long v0, p0

    .line 38
    const-wide/32 v2, 0x240c8400

    .line 39
    .line 40
    .line 41
    mul-long/2addr v0, v2

    .line 42
    sub-long/2addr p1, v0

    .line 43
    :cond_0
    return-wide p1

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public final v(IJ)J
    .locals 5

    .line 1
    iget v0, p0, Lp11/h;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lp11/h;->i:Lp11/m;

    .line 7
    .line 8
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    const v1, -0x116bc36e

    .line 12
    .line 13
    .line 14
    const v2, 0x116bd2d1

    .line 15
    .line 16
    .line 17
    invoke-static {p0, p1, v1, v2}, Ljp/je;->g(Ln11/a;III)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v0, p1, p2, p3}, Lp11/g;->e0(IJ)J

    .line 21
    .line 22
    .line 23
    move-result-wide p0

    .line 24
    return-wide p0

    .line 25
    :pswitch_0
    invoke-static {p1}, Ljava/lang/Math;->abs(I)I

    .line 26
    .line 27
    .line 28
    move-result v0

    .line 29
    iget-object v1, p0, Lp11/h;->i:Lp11/m;

    .line 30
    .line 31
    invoke-virtual {v1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 32
    .line 33
    .line 34
    const v2, -0x116bc36e

    .line 35
    .line 36
    .line 37
    const v3, 0x116bd2d1

    .line 38
    .line 39
    .line 40
    invoke-static {p0, v0, v2, v3}, Ljp/je;->g(Ln11/a;III)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v1, p2, p3}, Lp11/e;->W(J)I

    .line 44
    .line 45
    .line 46
    move-result p0

    .line 47
    if-ne p0, p1, :cond_0

    .line 48
    .line 49
    goto :goto_2

    .line 50
    :cond_0
    invoke-static {p2, p3}, Lp11/e;->Q(J)I

    .line 51
    .line 52
    .line 53
    move-result v0

    .line 54
    invoke-virtual {v1, p0}, Lp11/e;->V(I)I

    .line 55
    .line 56
    .line 57
    move-result p0

    .line 58
    invoke-virtual {v1, p1}, Lp11/e;->V(I)I

    .line 59
    .line 60
    .line 61
    move-result v2

    .line 62
    if-ge v2, p0, :cond_1

    .line 63
    .line 64
    move p0, v2

    .line 65
    :cond_1
    invoke-virtual {v1, p2, p3}, Lp11/e;->X(J)I

    .line 66
    .line 67
    .line 68
    move-result v2

    .line 69
    invoke-virtual {v1, v2, p2, p3}, Lp11/e;->U(IJ)I

    .line 70
    .line 71
    .line 72
    move-result v2

    .line 73
    if-le v2, p0, :cond_2

    .line 74
    .line 75
    goto :goto_0

    .line 76
    :cond_2
    move p0, v2

    .line 77
    :goto_0
    invoke-virtual {v1, p1, p2, p3}, Lp11/g;->e0(IJ)J

    .line 78
    .line 79
    .line 80
    move-result-wide p2

    .line 81
    invoke-virtual {v1, p2, p3}, Lp11/e;->W(J)I

    .line 82
    .line 83
    .line 84
    move-result v2

    .line 85
    const-wide/32 v3, 0x240c8400

    .line 86
    .line 87
    .line 88
    if-ge v2, p1, :cond_3

    .line 89
    .line 90
    add-long/2addr p2, v3

    .line 91
    goto :goto_1

    .line 92
    :cond_3
    if-le v2, p1, :cond_4

    .line 93
    .line 94
    sub-long/2addr p2, v3

    .line 95
    :cond_4
    :goto_1
    invoke-virtual {v1, p2, p3}, Lp11/e;->X(J)I

    .line 96
    .line 97
    .line 98
    move-result p1

    .line 99
    invoke-virtual {v1, p1, p2, p3}, Lp11/e;->U(IJ)I

    .line 100
    .line 101
    .line 102
    move-result p1

    .line 103
    sub-int/2addr p0, p1

    .line 104
    int-to-long p0, p0

    .line 105
    mul-long/2addr p0, v3

    .line 106
    add-long/2addr p0, p2

    .line 107
    iget-object p2, v1, Lp11/b;->C:Ln11/a;

    .line 108
    .line 109
    invoke-virtual {p2, v0, p0, p1}, Ln11/a;->v(IJ)J

    .line 110
    .line 111
    .line 112
    move-result-wide p2

    .line 113
    :goto_2
    return-wide p2

    .line 114
    nop

    .line 115
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public x(JI)J
    .locals 3

    .line 1
    iget v0, p0, Lp11/h;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2, p3}, Ln11/a;->x(JI)J

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    return-wide p0

    .line 11
    :pswitch_0
    iget-object v0, p0, Lp11/h;->i:Lp11/m;

    .line 12
    .line 13
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    const v1, -0x116bc36f

    .line 17
    .line 18
    .line 19
    const v2, 0x116bd2d2

    .line 20
    .line 21
    .line 22
    invoke-static {p0, p3, v1, v2}, Ljp/je;->g(Ln11/a;III)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {v0, p3, p1, p2}, Lp11/g;->e0(IJ)J

    .line 26
    .line 27
    .line 28
    move-result-wide p0

    .line 29
    return-wide p0

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public final z(JJ)J
    .locals 1

    .line 1
    iget v0, p0, Lp11/h;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-static {p3, p4}, Ljp/je;->e(J)I

    .line 7
    .line 8
    .line 9
    move-result p3

    .line 10
    invoke-virtual {p0, p3, p1, p2}, Lp11/h;->a(IJ)J

    .line 11
    .line 12
    .line 13
    move-result-wide p0

    .line 14
    return-wide p0

    .line 15
    :pswitch_0
    invoke-static {p3, p4}, Ljp/je;->e(J)I

    .line 16
    .line 17
    .line 18
    move-result p3

    .line 19
    invoke-virtual {p0, p3, p1, p2}, Lp11/h;->a(IJ)J

    .line 20
    .line 21
    .line 22
    move-result-wide p0

    .line 23
    return-wide p0

    .line 24
    nop

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method
