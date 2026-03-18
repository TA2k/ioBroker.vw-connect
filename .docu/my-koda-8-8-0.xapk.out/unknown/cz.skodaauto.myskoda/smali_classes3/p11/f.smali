.class public final Lp11/f;
.super Lq11/f;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic h:I

.field public final i:Lp11/m;


# direct methods
.method public constructor <init>(Lp11/m;Ln11/g;I)V
    .locals 0

    .line 1
    iput p3, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch p3, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    sget-object p3, Ln11/b;->o:Ln11/b;

    .line 7
    .line 8
    invoke-direct {p0, p3, p2}, Lq11/f;-><init>(Ln11/b;Ln11/g;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lp11/f;->i:Lp11/m;

    .line 12
    .line 13
    return-void

    .line 14
    :pswitch_0
    sget-object p3, Ln11/b;->s:Ln11/b;

    .line 15
    .line 16
    invoke-direct {p0, p3, p2}, Lq11/f;-><init>(Ln11/b;Ln11/g;)V

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lp11/f;->i:Lp11/m;

    .line 20
    .line 21
    return-void

    .line 22
    :pswitch_1
    sget-object p3, Ln11/b;->r:Ln11/b;

    .line 23
    .line 24
    invoke-direct {p0, p3, p2}, Lq11/f;-><init>(Ln11/b;Ln11/g;)V

    .line 25
    .line 26
    .line 27
    iput-object p1, p0, Lp11/f;->i:Lp11/m;

    .line 28
    .line 29
    return-void

    .line 30
    :pswitch_2
    sget-object p3, Ln11/b;->m:Ln11/b;

    .line 31
    .line 32
    invoke-direct {p0, p3, p2}, Lq11/f;-><init>(Ln11/b;Ln11/g;)V

    .line 33
    .line 34
    .line 35
    iput-object p1, p0, Lp11/f;->i:Lp11/m;

    .line 36
    .line 37
    return-void

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method


# virtual methods
.method public final b(J)I
    .locals 2

    .line 1
    iget v0, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 7
    .line 8
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 9
    .line 10
    .line 11
    invoke-static {p1, p2}, Lp11/e;->Q(J)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    return p0

    .line 16
    :pswitch_0
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 17
    .line 18
    invoke-virtual {p0, p1, p2}, Lp11/e;->X(J)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    invoke-virtual {p0, v0, p1, p2}, Lp11/e;->U(IJ)I

    .line 23
    .line 24
    .line 25
    move-result p0

    .line 26
    return p0

    .line 27
    :pswitch_1
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 28
    .line 29
    invoke-virtual {p0, p1, p2}, Lp11/e;->X(J)I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    invoke-virtual {p0, v0}, Lp11/e;->Y(I)J

    .line 34
    .line 35
    .line 36
    move-result-wide v0

    .line 37
    sub-long/2addr p1, v0

    .line 38
    const-wide/32 v0, 0x5265c00

    .line 39
    .line 40
    .line 41
    div-long/2addr p1, v0

    .line 42
    long-to-int p0, p1

    .line 43
    add-int/lit8 p0, p0, 0x1

    .line 44
    .line 45
    return p0

    .line 46
    :pswitch_2
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 47
    .line 48
    invoke-virtual {p0, p1, p2}, Lp11/e;->X(J)I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    invoke-virtual {p0, v0, p1, p2}, Lp11/g;->c0(IJ)I

    .line 53
    .line 54
    .line 55
    move-result v1

    .line 56
    invoke-virtual {p0, p1, p2, v0, v1}, Lp11/e;->P(JII)I

    .line 57
    .line 58
    .line 59
    move-result p0

    .line 60
    return p0

    .line 61
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public c(ILjava/util/Locale;)Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Lq11/a;->c(ILjava/util/Locale;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    invoke-static {p2}, Lp11/j;->b(Ljava/util/Locale;)Lp11/j;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    iget-object p0, p0, Lp11/j;->c:[Ljava/lang/String;

    .line 16
    .line 17
    aget-object p0, p0, p1

    .line 18
    .line 19
    return-object p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method

.method public f(ILjava/util/Locale;)Ljava/lang/String;
    .locals 1

    .line 1
    iget v0, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Lq11/a;->f(ILjava/util/Locale;)Ljava/lang/String;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0

    .line 11
    :pswitch_0
    invoke-static {p2}, Lp11/j;->b(Ljava/util/Locale;)Lp11/j;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    iget-object p0, p0, Lp11/j;->b:[Ljava/lang/String;

    .line 16
    .line 17
    aget-object p0, p0, p1

    .line 18
    .line 19
    return-object p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method

.method public k(Ljava/util/Locale;)I
    .locals 1

    .line 1
    iget v0, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1}, Lq11/a;->k(Ljava/util/Locale;)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    invoke-static {p1}, Lp11/j;->b(Ljava/util/Locale;)Lp11/j;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    iget p0, p0, Lp11/j;->k:I

    .line 16
    .line 17
    return p0

    .line 18
    nop

    .line 19
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method

.method public final l()I
    .locals 1

    .line 1
    iget v0, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x7

    .line 7
    return p0

    .line 8
    :pswitch_0
    const/16 p0, 0x35

    .line 9
    .line 10
    return p0

    .line 11
    :pswitch_1
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 12
    .line 13
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 14
    .line 15
    .line 16
    const/16 p0, 0x16e

    .line 17
    .line 18
    return p0

    .line 19
    :pswitch_2
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 20
    .line 21
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 22
    .line 23
    .line 24
    const/16 p0, 0x1f

    .line 25
    .line 26
    return p0

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public m(J)I
    .locals 1

    .line 1
    iget v0, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Ln11/a;->m(J)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 12
    .line 13
    invoke-virtual {p0, p1, p2}, Lp11/e;->W(J)I

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    invoke-virtual {p0, p1}, Lp11/e;->V(I)I

    .line 18
    .line 19
    .line 20
    move-result p0

    .line 21
    return p0

    .line 22
    :pswitch_1
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 23
    .line 24
    invoke-virtual {p0, p1, p2}, Lp11/e;->X(J)I

    .line 25
    .line 26
    .line 27
    move-result p1

    .line 28
    invoke-virtual {p0, p1}, Lp11/m;->a0(I)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-eqz p0, :cond_0

    .line 33
    .line 34
    const/16 p0, 0x16e

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :cond_0
    const/16 p0, 0x16d

    .line 38
    .line 39
    :goto_0
    return p0

    .line 40
    :pswitch_2
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 41
    .line 42
    invoke-virtual {p0, p1, p2}, Lp11/e;->X(J)I

    .line 43
    .line 44
    .line 45
    move-result v0

    .line 46
    invoke-virtual {p0, v0, p1, p2}, Lp11/g;->c0(IJ)I

    .line 47
    .line 48
    .line 49
    move-result p1

    .line 50
    invoke-virtual {p0, v0, p1}, Lp11/g;->b0(II)I

    .line 51
    .line 52
    .line 53
    move-result p0

    .line 54
    return p0

    .line 55
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public n(JI)I
    .locals 2

    .line 1
    iget v0, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2, p3}, Ln11/a;->n(JI)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    const/16 v0, 0x34

    .line 12
    .line 13
    if-le p3, v0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p0, p1, p2}, Lp11/f;->m(J)I

    .line 16
    .line 17
    .line 18
    move-result v0

    .line 19
    :cond_0
    return v0

    .line 20
    :pswitch_1
    iget-object v0, p0, Lp11/f;->i:Lp11/m;

    .line 21
    .line 22
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 23
    .line 24
    .line 25
    const/16 v0, 0x16d

    .line 26
    .line 27
    if-gt p3, v0, :cond_1

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    if-ge p3, v1, :cond_2

    .line 31
    .line 32
    :cond_1
    invoke-virtual {p0, p1, p2}, Lp11/f;->m(J)I

    .line 33
    .line 34
    .line 35
    move-result v0

    .line 36
    :cond_2
    return v0

    .line 37
    :pswitch_2
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 38
    .line 39
    invoke-virtual {p0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 40
    .line 41
    .line 42
    const/16 v0, 0x1c

    .line 43
    .line 44
    if-gt p3, v0, :cond_3

    .line 45
    .line 46
    const/4 v1, 0x1

    .line 47
    if-ge p3, v1, :cond_4

    .line 48
    .line 49
    :cond_3
    invoke-virtual {p0, p1, p2}, Lp11/e;->X(J)I

    .line 50
    .line 51
    .line 52
    move-result p3

    .line 53
    invoke-virtual {p0, p3, p1, p2}, Lp11/g;->c0(IJ)I

    .line 54
    .line 55
    .line 56
    move-result p1

    .line 57
    invoke-virtual {p0, p3, p1}, Lp11/g;->b0(II)I

    .line 58
    .line 59
    .line 60
    move-result v0

    .line 61
    :cond_4
    return v0

    .line 62
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final o()I
    .locals 0

    .line 1
    iget p0, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 p0, 0x1

    .line 7
    return p0

    .line 8
    :pswitch_0
    const/4 p0, 0x1

    .line 9
    return p0

    .line 10
    :pswitch_1
    const/4 p0, 0x1

    .line 11
    return p0

    .line 12
    :pswitch_2
    const/4 p0, 0x1

    .line 13
    return p0

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final p()Ln11/g;
    .locals 1

    .line 1
    iget v0, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 7
    .line 8
    iget-object p0, p0, Lp11/b;->l:Ln11/g;

    .line 9
    .line 10
    return-object p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 12
    .line 13
    iget-object p0, p0, Lp11/b;->m:Ln11/g;

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_1
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 17
    .line 18
    iget-object p0, p0, Lp11/b;->o:Ln11/g;

    .line 19
    .line 20
    return-object p0

    .line 21
    :pswitch_2
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 22
    .line 23
    iget-object p0, p0, Lp11/b;->n:Ln11/g;

    .line 24
    .line 25
    return-object p0

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public r(J)Z
    .locals 1

    .line 1
    iget v0, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Lq11/a;->r(J)Z

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 12
    .line 13
    invoke-virtual {p0, p1, p2}, Lp11/g;->d0(J)Z

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0

    .line 18
    :pswitch_1
    iget-object p0, p0, Lp11/f;->i:Lp11/m;

    .line 19
    .line 20
    invoke-virtual {p0, p1, p2}, Lp11/g;->d0(J)Z

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    return p0

    .line 25
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public t(J)J
    .locals 2

    .line 1
    iget v0, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Lq11/f;->t(J)J

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    return-wide p0

    .line 11
    :pswitch_0
    const-wide/32 v0, 0xf731400

    .line 12
    .line 13
    .line 14
    add-long/2addr p1, v0

    .line 15
    invoke-super {p0, p1, p2}, Lq11/f;->t(J)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    return-wide p0

    .line 20
    nop

    .line 21
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public u(J)J
    .locals 2

    .line 1
    iget v0, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Lq11/f;->u(J)J

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    return-wide p0

    .line 11
    :pswitch_0
    const-wide/32 v0, 0xf731400

    .line 12
    .line 13
    .line 14
    add-long/2addr p1, v0

    .line 15
    invoke-super {p0, p1, p2}, Lq11/f;->u(J)J

    .line 16
    .line 17
    .line 18
    move-result-wide p0

    .line 19
    sub-long/2addr p0, v0

    .line 20
    return-wide p0

    .line 21
    :pswitch_data_0
    .packed-switch 0x2
        :pswitch_0
    .end packed-switch
.end method

.method public y(Ljava/lang/String;Ljava/util/Locale;)I
    .locals 1

    .line 1
    iget v0, p0, Lp11/f;->h:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Lq11/a;->y(Ljava/lang/String;Ljava/util/Locale;)I

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0

    .line 11
    :pswitch_0
    invoke-static {p2}, Lp11/j;->b(Ljava/util/Locale;)Lp11/j;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    iget-object p0, p0, Lp11/j;->h:Ljava/util/TreeMap;

    .line 16
    .line 17
    invoke-virtual {p0, p1}, Ljava/util/TreeMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    check-cast p0, Ljava/lang/Integer;

    .line 22
    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    invoke-virtual {p0}, Ljava/lang/Integer;->intValue()I

    .line 26
    .line 27
    .line 28
    move-result p0

    .line 29
    return p0

    .line 30
    :cond_0
    new-instance p0, Ln11/i;

    .line 31
    .line 32
    sget-object p2, Ln11/b;->s:Ln11/b;

    .line 33
    .line 34
    invoke-direct {p0, p2, p1}, Ln11/i;-><init>(Ln11/b;Ljava/lang/String;)V

    .line 35
    .line 36
    .line 37
    throw p0

    .line 38
    nop

    .line 39
    :pswitch_data_0
    .packed-switch 0x3
        :pswitch_0
    .end packed-switch
.end method
