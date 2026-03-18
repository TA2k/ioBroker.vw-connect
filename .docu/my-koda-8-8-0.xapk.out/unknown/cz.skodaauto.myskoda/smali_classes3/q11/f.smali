.class public abstract Lq11/f;
.super Lq11/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic e:I

.field public final f:J

.field public final g:Ln11/g;


# direct methods
.method public constructor <init>(Ln11/b;J)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Lq11/f;->e:I

    .line 7
    invoke-direct {p0, p1}, Lq11/a;-><init>(Ln11/b;)V

    .line 8
    iput-wide p2, p0, Lq11/f;->f:J

    .line 9
    new-instance p2, Lq11/e;

    .line 10
    iget-object p1, p1, Ln11/b;->f:Ln11/h;

    .line 11
    invoke-direct {p2, p0, p1}, Lq11/e;-><init>(Lq11/f;Ln11/h;)V

    iput-object p2, p0, Lq11/f;->g:Ln11/g;

    return-void
.end method

.method public constructor <init>(Ln11/b;Ln11/g;)V
    .locals 4

    const/4 v0, 0x1

    iput v0, p0, Lq11/f;->e:I

    .line 1
    invoke-direct {p0, p1}, Lq11/a;-><init>(Ln11/b;)V

    .line 2
    invoke-virtual {p2}, Ln11/g;->e()Z

    move-result p1

    if-eqz p1, :cond_1

    .line 3
    invoke-virtual {p2}, Ln11/g;->d()J

    move-result-wide v0

    iput-wide v0, p0, Lq11/f;->f:J

    const-wide/16 v2, 0x1

    cmp-long p1, v0, v2

    if-ltz p1, :cond_0

    .line 4
    iput-object p2, p0, Lq11/f;->g:Ln11/g;

    return-void

    .line 5
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "The unit milliseconds must be at least 1"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0

    .line 6
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Unit duration field must be precise"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method


# virtual methods
.method public final i()Ln11/g;
    .locals 1

    .line 1
    iget v0, p0, Lq11/f;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lq11/f;->g:Ln11/g;

    .line 7
    .line 8
    return-object p0

    .line 9
    :pswitch_0
    iget-object p0, p0, Lq11/f;->g:Ln11/g;

    .line 10
    .line 11
    check-cast p0, Lq11/e;

    .line 12
    .line 13
    return-object p0

    .line 14
    nop

    .line 15
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.method public o()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public t(J)J
    .locals 5

    .line 1
    iget v0, p0, Lq11/f;->e:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    invoke-super {p0, p1, p2}, Lq11/a;->t(J)J

    .line 7
    .line 8
    .line 9
    move-result-wide p0

    .line 10
    return-wide p0

    .line 11
    :pswitch_0
    const-wide/16 v0, 0x0

    .line 12
    .line 13
    cmp-long v0, p1, v0

    .line 14
    .line 15
    iget-wide v1, p0, Lq11/f;->f:J

    .line 16
    .line 17
    if-ltz v0, :cond_0

    .line 18
    .line 19
    rem-long/2addr p1, v1

    .line 20
    goto :goto_0

    .line 21
    :cond_0
    const-wide/16 v3, 0x1

    .line 22
    .line 23
    add-long/2addr p1, v3

    .line 24
    rem-long/2addr p1, v1

    .line 25
    add-long/2addr p1, v1

    .line 26
    sub-long/2addr p1, v3

    .line 27
    :goto_0
    return-wide p1

    .line 28
    nop

    .line 29
    :pswitch_data_0
    .packed-switch 0x1
        :pswitch_0
    .end packed-switch
.end method

.method public u(J)J
    .locals 5

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    cmp-long v0, p1, v0

    .line 4
    .line 5
    iget-wide v1, p0, Lq11/f;->f:J

    .line 6
    .line 7
    if-ltz v0, :cond_0

    .line 8
    .line 9
    rem-long v0, p1, v1

    .line 10
    .line 11
    sub-long/2addr p1, v0

    .line 12
    return-wide p1

    .line 13
    :cond_0
    const-wide/16 v3, 0x1

    .line 14
    .line 15
    add-long/2addr p1, v3

    .line 16
    rem-long v3, p1, v1

    .line 17
    .line 18
    sub-long/2addr p1, v3

    .line 19
    sub-long/2addr p1, v1

    .line 20
    return-wide p1
.end method

.method public v(IJ)J
    .locals 2

    .line 1
    invoke-virtual {p0}, Lq11/f;->o()I

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-virtual {p0, p2, p3, p1}, Lq11/f;->n(JI)I

    .line 6
    .line 7
    .line 8
    move-result v1

    .line 9
    invoke-static {p0, p1, v0, v1}, Ljp/je;->g(Ln11/a;III)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {p0, p2, p3}, Ln11/a;->b(J)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    sub-int/2addr p1, v0

    .line 17
    int-to-long v0, p1

    .line 18
    iget-wide p0, p0, Lq11/f;->f:J

    .line 19
    .line 20
    mul-long/2addr v0, p0

    .line 21
    add-long/2addr v0, p2

    .line 22
    return-wide v0
.end method

.method public abstract z(JJ)J
.end method
