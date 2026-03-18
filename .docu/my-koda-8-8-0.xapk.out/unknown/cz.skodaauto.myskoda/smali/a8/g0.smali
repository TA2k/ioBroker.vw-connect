.class public final La8/g0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lm8/x;
.implements Ln8/a;
.implements La8/k1;


# instance fields
.field public d:Lm8/x;

.field public e:Ln8/a;

.field public f:Lm8/x;

.field public g:Ln8/a;


# virtual methods
.method public final a(ILjava/lang/Object;)V
    .locals 1

    .line 1
    const/4 v0, 0x7

    .line 2
    if-eq p1, v0, :cond_3

    .line 3
    .line 4
    const/16 v0, 0x8

    .line 5
    .line 6
    if-eq p1, v0, :cond_2

    .line 7
    .line 8
    const/16 v0, 0x2710

    .line 9
    .line 10
    if-eq p1, v0, :cond_0

    .line 11
    .line 12
    return-void

    .line 13
    :cond_0
    check-cast p2, Ln8/k;

    .line 14
    .line 15
    if-nez p2, :cond_1

    .line 16
    .line 17
    const/4 p1, 0x0

    .line 18
    iput-object p1, p0, La8/g0;->f:Lm8/x;

    .line 19
    .line 20
    iput-object p1, p0, La8/g0;->g:Ln8/a;

    .line 21
    .line 22
    return-void

    .line 23
    :cond_1
    invoke-virtual {p2}, Ln8/k;->getVideoFrameMetadataListener()Lm8/x;

    .line 24
    .line 25
    .line 26
    move-result-object p1

    .line 27
    iput-object p1, p0, La8/g0;->f:Lm8/x;

    .line 28
    .line 29
    invoke-virtual {p2}, Ln8/k;->getCameraMotionListener()Ln8/a;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    iput-object p1, p0, La8/g0;->g:Ln8/a;

    .line 34
    .line 35
    return-void

    .line 36
    :cond_2
    check-cast p2, Ln8/a;

    .line 37
    .line 38
    iput-object p2, p0, La8/g0;->e:Ln8/a;

    .line 39
    .line 40
    return-void

    .line 41
    :cond_3
    check-cast p2, Lm8/x;

    .line 42
    .line 43
    iput-object p2, p0, La8/g0;->d:Lm8/x;

    .line 44
    .line 45
    return-void
.end method

.method public final b(JJLt7/o;Landroid/media/MediaFormat;)V
    .locals 7

    .line 1
    iget-object v0, p0, La8/g0;->f:Lm8/x;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    move-wide v1, p1

    .line 6
    move-wide v3, p3

    .line 7
    move-object v5, p5

    .line 8
    move-object v6, p6

    .line 9
    invoke-interface/range {v0 .. v6}, Lm8/x;->b(JJLt7/o;Landroid/media/MediaFormat;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, La8/g0;->d:Lm8/x;

    .line 13
    .line 14
    if-eqz p0, :cond_1

    .line 15
    .line 16
    invoke-interface/range {p0 .. p6}, Lm8/x;->b(JJLt7/o;Landroid/media/MediaFormat;)V

    .line 17
    .line 18
    .line 19
    :cond_1
    return-void
.end method

.method public final c(J[F)V
    .locals 1

    .line 1
    iget-object v0, p0, La8/g0;->g:Ln8/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0, p1, p2, p3}, Ln8/a;->c(J[F)V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object p0, p0, La8/g0;->e:Ln8/a;

    .line 9
    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    invoke-interface {p0, p1, p2, p3}, Ln8/a;->c(J[F)V

    .line 13
    .line 14
    .line 15
    :cond_1
    return-void
.end method

.method public final d()V
    .locals 1

    .line 1
    iget-object v0, p0, La8/g0;->g:Ln8/a;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    invoke-interface {v0}, Ln8/a;->d()V

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object p0, p0, La8/g0;->e:Ln8/a;

    .line 9
    .line 10
    if-eqz p0, :cond_1

    .line 11
    .line 12
    invoke-interface {p0}, Ln8/a;->d()V

    .line 13
    .line 14
    .line 15
    :cond_1
    return-void
.end method
