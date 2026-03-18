.class public final Lk1/t;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lk1/t;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lk1/t;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lk1/t;->a:Lk1/t;

    .line 7
    .line 8
    return-void
.end method

.method public static synthetic c(Lk1/t;Lx2/s;)Lx2/s;
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    invoke-virtual {p0, p1, v0}, Lk1/t;->b(Lx2/s;Z)Lx2/s;

    .line 3
    .line 4
    .line 5
    move-result-object p0

    .line 6
    return-object p0
.end method


# virtual methods
.method public final a(Lx2/h;Lx2/s;)Lx2/s;
    .locals 0

    .line 1
    invoke-static {p1, p2}, Lia/b;->p(Lx2/h;Lx2/s;)Lx2/s;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final b(Lx2/s;Z)Lx2/s;
    .locals 4

    .line 1
    const/high16 p0, 0x3f800000    # 1.0f

    .line 2
    .line 3
    float-to-double v0, p0

    .line 4
    const-wide/16 v2, 0x0

    .line 5
    .line 6
    cmpl-double v0, v0, v2

    .line 7
    .line 8
    if-lez v0, :cond_0

    .line 9
    .line 10
    goto :goto_0

    .line 11
    :cond_0
    const-string v0, "invalid weight; must be greater than zero"

    .line 12
    .line 13
    invoke-static {v0}, Ll1/a;->a(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    :goto_0
    new-instance v0, Landroidx/compose/foundation/layout/LayoutWeightElement;

    .line 17
    .line 18
    invoke-direct {v0, p0, p2}, Landroidx/compose/foundation/layout/LayoutWeightElement;-><init>(FZ)V

    .line 19
    .line 20
    .line 21
    invoke-interface {p1, v0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 22
    .line 23
    .line 24
    move-result-object p0

    .line 25
    return-object p0
.end method
