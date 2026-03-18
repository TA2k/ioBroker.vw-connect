.class public final Lh2/b8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk1/z0;


# instance fields
.field public final a:Ll2/j1;


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    int-to-float v0, v0

    .line 6
    new-instance v1, Lk1/a1;

    .line 7
    .line 8
    invoke-direct {v1, v0, v0, v0, v0}, Lk1/a1;-><init>(FFFF)V

    .line 9
    .line 10
    .line 11
    invoke-static {v1}, Ll2/b;->n(Ljava/lang/Object;)Ll2/j1;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    iput-object v0, p0, Lh2/b8;->a:Ll2/j1;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final a(Lt4/m;)F
    .locals 0

    .line 1
    iget-object p0, p0, Lh2/b8;->a:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lk1/z0;

    .line 8
    .line 9
    invoke-interface {p0, p1}, Lk1/z0;->a(Lt4/m;)F

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final b(Lt4/m;)F
    .locals 0

    .line 1
    iget-object p0, p0, Lh2/b8;->a:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lk1/z0;

    .line 8
    .line 9
    invoke-interface {p0, p1}, Lk1/z0;->b(Lt4/m;)F

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final c()F
    .locals 0

    .line 1
    iget-object p0, p0, Lh2/b8;->a:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lk1/z0;

    .line 8
    .line 9
    invoke-interface {p0}, Lk1/z0;->c()F

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public final d()F
    .locals 0

    .line 1
    iget-object p0, p0, Lh2/b8;->a:Ll2/j1;

    .line 2
    .line 3
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lk1/z0;

    .line 8
    .line 9
    invoke-interface {p0}, Lk1/z0;->d()F

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method
