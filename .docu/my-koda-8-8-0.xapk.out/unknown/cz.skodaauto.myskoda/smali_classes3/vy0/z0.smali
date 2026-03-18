.class public abstract Lvy0/z0;
.super Lvy0/x;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic h:I


# instance fields
.field public e:J

.field public f:Z

.field public g:Lmx0/l;


# virtual methods
.method public final W(I)Lvy0/x;
    .locals 0

    .line 1
    invoke-static {p1}, Laz0/b;->a(I)V

    .line 2
    .line 3
    .line 4
    return-object p0
.end method

.method public final e0(Z)V
    .locals 4

    .line 1
    iget-wide v0, p0, Lvy0/z0;->e:J

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    const-wide v2, 0x100000000L

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const-wide/16 v2, 0x1

    .line 12
    .line 13
    :goto_0
    sub-long/2addr v0, v2

    .line 14
    iput-wide v0, p0, Lvy0/z0;->e:J

    .line 15
    .line 16
    const-wide/16 v2, 0x0

    .line 17
    .line 18
    cmp-long p1, v0, v2

    .line 19
    .line 20
    if-lez p1, :cond_1

    .line 21
    .line 22
    goto :goto_1

    .line 23
    :cond_1
    iget-boolean p1, p0, Lvy0/z0;->f:Z

    .line 24
    .line 25
    if-eqz p1, :cond_2

    .line 26
    .line 27
    invoke-virtual {p0}, Lvy0/z0;->shutdown()V

    .line 28
    .line 29
    .line 30
    :cond_2
    :goto_1
    return-void
.end method

.method public final h0(Lvy0/n0;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lvy0/z0;->g:Lmx0/l;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lmx0/l;

    .line 6
    .line 7
    invoke-direct {v0}, Lmx0/l;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lvy0/z0;->g:Lmx0/l;

    .line 11
    .line 12
    :cond_0
    invoke-virtual {v0, p1}, Lmx0/l;->addLast(Ljava/lang/Object;)V

    .line 13
    .line 14
    .line 15
    return-void
.end method

.method public abstract k0()Ljava/lang/Thread;
.end method

.method public final l0(Z)V
    .locals 4

    .line 1
    iget-wide v0, p0, Lvy0/z0;->e:J

    .line 2
    .line 3
    if-eqz p1, :cond_0

    .line 4
    .line 5
    const-wide v2, 0x100000000L

    .line 6
    .line 7
    .line 8
    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const-wide/16 v2, 0x1

    .line 12
    .line 13
    :goto_0
    add-long/2addr v2, v0

    .line 14
    iput-wide v2, p0, Lvy0/z0;->e:J

    .line 15
    .line 16
    if-nez p1, :cond_1

    .line 17
    .line 18
    const/4 p1, 0x1

    .line 19
    iput-boolean p1, p0, Lvy0/z0;->f:Z

    .line 20
    .line 21
    :cond_1
    return-void
.end method

.method public abstract n0()J
.end method

.method public final q0()Z
    .locals 1

    .line 1
    iget-object p0, p0, Lvy0/z0;->g:Lmx0/l;

    .line 2
    .line 3
    if-nez p0, :cond_0

    .line 4
    .line 5
    goto :goto_1

    .line 6
    :cond_0
    invoke-virtual {p0}, Lmx0/l;->isEmpty()Z

    .line 7
    .line 8
    .line 9
    move-result v0

    .line 10
    if-eqz v0, :cond_1

    .line 11
    .line 12
    const/4 p0, 0x0

    .line 13
    goto :goto_0

    .line 14
    :cond_1
    invoke-virtual {p0}, Lmx0/l;->removeFirst()Ljava/lang/Object;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    :goto_0
    check-cast p0, Lvy0/n0;

    .line 19
    .line 20
    if-nez p0, :cond_2

    .line 21
    .line 22
    :goto_1
    const/4 p0, 0x0

    .line 23
    return p0

    .line 24
    :cond_2
    invoke-virtual {p0}, Lvy0/n0;->run()V

    .line 25
    .line 26
    .line 27
    const/4 p0, 0x1

    .line 28
    return p0
.end method

.method public r0(JLvy0/w0;)V
    .locals 0

    .line 1
    sget-object p0, Lvy0/f0;->l:Lvy0/f0;

    .line 2
    .line 3
    invoke-virtual {p0, p1, p2, p3}, Lvy0/y0;->B0(JLvy0/w0;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public abstract shutdown()V
.end method
