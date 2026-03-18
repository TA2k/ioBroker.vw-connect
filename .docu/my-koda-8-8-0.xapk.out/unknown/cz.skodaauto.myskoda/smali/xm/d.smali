.class public final Lxm/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lxm/b;


# instance fields
.field public final d:Lhn/a;

.field public e:F


# direct methods
.method public constructor <init>(Ljava/util/List;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/high16 v0, -0x40800000    # -1.0f

    .line 5
    .line 6
    iput v0, p0, Lxm/d;->e:F

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    invoke-interface {p1, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p1

    .line 13
    check-cast p1, Lhn/a;

    .line 14
    .line 15
    iput-object p1, p0, Lxm/d;->d:Lhn/a;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public final b(F)Z
    .locals 1

    .line 1
    iget v0, p0, Lxm/d;->e:F

    .line 2
    .line 3
    cmpl-float v0, v0, p1

    .line 4
    .line 5
    if-nez v0, :cond_0

    .line 6
    .line 7
    const/4 p0, 0x1

    .line 8
    return p0

    .line 9
    :cond_0
    iput p1, p0, Lxm/d;->e:F

    .line 10
    .line 11
    const/4 p0, 0x0

    .line 12
    return p0
.end method

.method public final c()Lhn/a;
    .locals 0

    .line 1
    iget-object p0, p0, Lxm/d;->d:Lhn/a;

    .line 2
    .line 3
    return-object p0
.end method

.method public final d(F)Z
    .locals 0

    .line 1
    iget-object p0, p0, Lxm/d;->d:Lhn/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Lhn/a;->c()Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    xor-int/lit8 p0, p0, 0x1

    .line 8
    .line 9
    return p0
.end method

.method public final f()F
    .locals 0

    .line 1
    iget-object p0, p0, Lxm/d;->d:Lhn/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Lhn/a;->b()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final isEmpty()Z
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final j()F
    .locals 0

    .line 1
    iget-object p0, p0, Lxm/d;->d:Lhn/a;

    .line 2
    .line 3
    invoke-virtual {p0}, Lhn/a;->a()F

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method
