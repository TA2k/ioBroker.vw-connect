.class public final Le1/i0;
.super Landroid/widget/EdgeEffect;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:F

.field public b:F


# direct methods
.method public constructor <init>(Landroid/content/Context;)V
    .locals 1

    .line 1
    invoke-direct {p0, p1}, Landroid/widget/EdgeEffect;-><init>(Landroid/content/Context;)V

    .line 2
    .line 3
    .line 4
    invoke-static {p1}, Lkp/z8;->a(Landroid/content/Context;)Lt4/e;

    .line 5
    .line 6
    .line 7
    move-result-object p1

    .line 8
    const/4 v0, 0x1

    .line 9
    int-to-float v0, v0

    .line 10
    iget p1, p1, Lt4/e;->d:F

    .line 11
    .line 12
    mul-float/2addr p1, v0

    .line 13
    iput p1, p0, Le1/i0;->a:F

    .line 14
    .line 15
    return-void
.end method


# virtual methods
.method public final onAbsorb(I)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Le1/i0;->b:F

    .line 3
    .line 4
    invoke-super {p0, p1}, Landroid/widget/EdgeEffect;->onAbsorb(I)V

    .line 5
    .line 6
    .line 7
    return-void
.end method

.method public final onPull(F)V
    .locals 1

    const/4 v0, 0x0

    .line 3
    iput v0, p0, Le1/i0;->b:F

    .line 4
    invoke-super {p0, p1}, Landroid/widget/EdgeEffect;->onPull(F)V

    return-void
.end method

.method public final onPull(FF)V
    .locals 1

    const/4 v0, 0x0

    .line 1
    iput v0, p0, Le1/i0;->b:F

    .line 2
    invoke-super {p0, p1, p2}, Landroid/widget/EdgeEffect;->onPull(FF)V

    return-void
.end method

.method public final onRelease()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput v0, p0, Le1/i0;->b:F

    .line 3
    .line 4
    invoke-super {p0}, Landroid/widget/EdgeEffect;->onRelease()V

    .line 5
    .line 6
    .line 7
    return-void
.end method
