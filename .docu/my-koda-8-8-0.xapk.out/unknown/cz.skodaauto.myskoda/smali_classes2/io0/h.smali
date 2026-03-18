.class public final Lio0/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lt7/j0;


# instance fields
.field public final synthetic d:Ll2/f1;

.field public final synthetic e:F

.field public final synthetic f:Ll2/b1;

.field public final synthetic g:Ll2/b1;


# direct methods
.method public constructor <init>(Ll2/f1;FLl2/b1;Ll2/b1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio0/h;->d:Ll2/f1;

    .line 5
    .line 6
    iput p2, p0, Lio0/h;->e:F

    .line 7
    .line 8
    iput-object p3, p0, Lio0/h;->f:Ll2/b1;

    .line 9
    .line 10
    iput-object p4, p0, Lio0/h;->g:Ll2/b1;

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final a(Lt7/a1;)V
    .locals 4

    .line 1
    const-string v0, "videoSize"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget v0, p1, Lt7/a1;->a:I

    .line 7
    .line 8
    iget v1, p1, Lt7/a1;->b:I

    .line 9
    .line 10
    if-eq v0, v1, :cond_0

    .line 11
    .line 12
    new-instance v2, Lh50/q0;

    .line 13
    .line 14
    const/16 v3, 0xd

    .line 15
    .line 16
    invoke-direct {v2, p1, v3}, Lh50/q0;-><init>(Ljava/lang/Object;I)V

    .line 17
    .line 18
    .line 19
    invoke-static {p0, v2}, Llp/nd;->l(Ljava/lang/Object;Lay0/a;)V

    .line 20
    .line 21
    .line 22
    int-to-float p1, v1

    .line 23
    int-to-float v0, v0

    .line 24
    div-float/2addr p1, v0

    .line 25
    iget v0, p0, Lio0/h;->e:F

    .line 26
    .line 27
    mul-float/2addr p1, v0

    .line 28
    invoke-static {p1}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 29
    .line 30
    .line 31
    move-result-object p1

    .line 32
    iget-object p0, p0, Lio0/h;->d:Ll2/f1;

    .line 33
    .line 34
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 35
    .line 36
    .line 37
    return-void

    .line 38
    :cond_0
    iget-object p0, p0, Lio0/h;->f:Ll2/b1;

    .line 39
    .line 40
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 41
    .line 42
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 43
    .line 44
    .line 45
    return-void
.end method

.method public final r()V
    .locals 2

    .line 1
    iget-object v0, p0, Lio0/h;->f:Ll2/b1;

    .line 2
    .line 3
    sget-object v1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 4
    .line 5
    invoke-interface {v0, v1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    new-instance v0, Lhz/a;

    .line 9
    .line 10
    const/16 v1, 0x1d

    .line 11
    .line 12
    invoke-direct {v0, v1}, Lhz/a;-><init>(I)V

    .line 13
    .line 14
    .line 15
    invoke-static {p0, v0}, Llp/nd;->l(Ljava/lang/Object;Lay0/a;)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public final z(Lt7/f0;)V
    .locals 1

    .line 1
    const-string v0, "error"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lio0/h;->g:Ll2/b1;

    .line 7
    .line 8
    sget-object p1, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    .line 9
    .line 10
    invoke-interface {p0, p1}, Ll2/b1;->setValue(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    return-void
.end method
