.class public final Lk1/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk1/h1;


# static fields
.field public static final a:Lk1/k0;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lk1/k0;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lk1/k0;->a:Lk1/k0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lx2/s;F)Lx2/s;
    .locals 4

    .line 1
    float-to-double v0, p2

    .line 2
    const-wide/16 v2, 0x0

    .line 3
    .line 4
    cmpl-double p0, v0, v2

    .line 5
    .line 6
    if-lez p0, :cond_0

    .line 7
    .line 8
    goto :goto_0

    .line 9
    :cond_0
    const-string p0, "invalid weight; must be greater than zero"

    .line 10
    .line 11
    invoke-static {p0}, Ll1/a;->a(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    :goto_0
    new-instance p0, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 15
    .line 16
    const v0, 0x7f7fffff    # Float.MAX_VALUE

    .line 17
    .line 18
    .line 19
    cmpl-float v1, p2, v0

    .line 20
    .line 21
    if-lez v1, :cond_1

    .line 22
    .line 23
    move p2, v0

    .line 24
    :cond_1
    const/4 v0, 0x1

    .line 25
    invoke-direct {p0, p2, v0}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 26
    .line 27
    .line 28
    invoke-interface {p1, p0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method

.method public final b(Lx2/s;Lx2/i;)Lx2/s;
    .locals 0

    .line 1
    new-instance p0, Landroidx/compose/foundation/layout/VerticalAlignElement;

    .line 2
    .line 3
    invoke-direct {p0, p2}, Landroidx/compose/foundation/layout/VerticalAlignElement;-><init>(Lx2/i;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p1, p0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    return-object p0
.end method
