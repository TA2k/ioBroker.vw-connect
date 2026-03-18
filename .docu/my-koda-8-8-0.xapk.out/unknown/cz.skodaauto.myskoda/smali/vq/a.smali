.class public final Lvq/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:I


# direct methods
.method static constructor <clinit>()V
    .locals 0

    .line 1
    return-void
.end method

.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    new-instance v0, Landroid/graphics/Path;

    .line 5
    .line 6
    invoke-direct {v0}, Landroid/graphics/Path;-><init>()V

    .line 7
    .line 8
    .line 9
    new-instance v0, Landroid/graphics/Paint;

    .line 10
    .line 11
    invoke-direct {v0}, Landroid/graphics/Paint;-><init>()V

    .line 12
    .line 13
    .line 14
    new-instance v1, Landroid/graphics/Paint;

    .line 15
    .line 16
    invoke-direct {v1}, Landroid/graphics/Paint;-><init>()V

    .line 17
    .line 18
    .line 19
    const/16 v2, 0x44

    .line 20
    .line 21
    const/high16 v3, -0x1000000

    .line 22
    .line 23
    invoke-static {v3, v2}, Ls5/a;->e(II)I

    .line 24
    .line 25
    .line 26
    move-result v2

    .line 27
    iput v2, p0, Lvq/a;->a:I

    .line 28
    .line 29
    const/16 v2, 0x14

    .line 30
    .line 31
    invoke-static {v3, v2}, Ls5/a;->e(II)I

    .line 32
    .line 33
    .line 34
    const/4 v2, 0x0

    .line 35
    invoke-static {v3, v2}, Ls5/a;->e(II)I

    .line 36
    .line 37
    .line 38
    iget p0, p0, Lvq/a;->a:I

    .line 39
    .line 40
    invoke-virtual {v1, p0}, Landroid/graphics/Paint;->setColor(I)V

    .line 41
    .line 42
    .line 43
    invoke-virtual {v0, v2}, Landroid/graphics/Paint;->setColor(I)V

    .line 44
    .line 45
    .line 46
    new-instance p0, Landroid/graphics/Paint;

    .line 47
    .line 48
    const/4 v0, 0x4

    .line 49
    invoke-direct {p0, v0}, Landroid/graphics/Paint;-><init>(I)V

    .line 50
    .line 51
    .line 52
    sget-object v0, Landroid/graphics/Paint$Style;->FILL:Landroid/graphics/Paint$Style;

    .line 53
    .line 54
    invoke-virtual {p0, v0}, Landroid/graphics/Paint;->setStyle(Landroid/graphics/Paint$Style;)V

    .line 55
    .line 56
    .line 57
    new-instance v0, Landroid/graphics/Paint;

    .line 58
    .line 59
    invoke-direct {v0, p0}, Landroid/graphics/Paint;-><init>(Landroid/graphics/Paint;)V

    .line 60
    .line 61
    .line 62
    return-void
.end method
