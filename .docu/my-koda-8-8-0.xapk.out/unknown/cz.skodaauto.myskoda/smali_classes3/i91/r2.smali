.class public final Li91/r2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:Ll2/j1;

.field public b:Ll2/j1;

.field public c:Ll2/j1;

.field public d:Ll2/j1;

.field public e:Ll2/j1;


# virtual methods
.method public final a()F
    .locals 0

    .line 1
    iget-object p0, p0, Li91/r2;->a:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lt4/f;

    .line 8
    .line 9
    iget p0, p0, Lt4/f;->d:F

    .line 10
    .line 11
    return p0
.end method

.method public final b()F
    .locals 0

    .line 1
    iget-object p0, p0, Li91/r2;->b:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lt4/f;

    .line 8
    .line 9
    iget p0, p0, Lt4/f;->d:F

    .line 10
    .line 11
    return p0
.end method

.method public final c()Li91/s2;
    .locals 0

    .line 1
    iget-object p0, p0, Li91/r2;->e:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Li91/s2;

    .line 8
    .line 9
    return-object p0
.end method

.method public final d(F)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Li91/r2;->a()F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p1, v0}, Lt4/f;->a(FF)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Li91/r2;->a:Ll2/j1;

    .line 12
    .line 13
    new-instance v0, Lt4/f;

    .line 14
    .line 15
    invoke-direct {v0, p1}, Lt4/f;-><init>(F)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void
.end method

.method public final e(F)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Li91/r2;->b()F

    .line 2
    .line 3
    .line 4
    move-result v0

    .line 5
    invoke-static {p1, v0}, Lt4/f;->a(FF)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    iget-object p0, p0, Li91/r2;->b:Ll2/j1;

    .line 12
    .line 13
    new-instance v0, Lt4/f;

    .line 14
    .line 15
    invoke-direct {v0, p1}, Lt4/f;-><init>(F)V

    .line 16
    .line 17
    .line 18
    invoke-virtual {p0, v0}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 19
    .line 20
    .line 21
    :cond_0
    return-void
.end method

.method public final f(Li91/s2;)V
    .locals 1

    .line 1
    invoke-virtual {p0}, Li91/r2;->c()Li91/s2;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    if-eq p1, v0, :cond_0

    .line 6
    .line 7
    iget-object p0, p0, Li91/r2;->e:Ll2/j1;

    .line 8
    .line 9
    invoke-virtual {p0, p1}, Ll2/j1;->setValue(Ljava/lang/Object;)V

    .line 10
    .line 11
    .line 12
    :cond_0
    return-void
.end method
