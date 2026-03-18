.class public final Landroidx/compose/foundation/layout/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lk1/q;


# static fields
.field public static final a:Landroidx/compose/foundation/layout/b;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Landroidx/compose/foundation/layout/b;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Landroidx/compose/foundation/layout/b;->a:Landroidx/compose/foundation/layout/b;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lx2/s;Lx2/e;)Lx2/s;
    .locals 1

    .line 1
    new-instance p0, Landroidx/compose/foundation/layout/BoxChildDataElement;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-direct {p0, p2, v0}, Landroidx/compose/foundation/layout/BoxChildDataElement;-><init>(Lx2/e;Z)V

    .line 5
    .line 6
    .line 7
    invoke-interface {p1, p0}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method

.method public final b()Lx2/s;
    .locals 2

    .line 1
    new-instance p0, Landroidx/compose/foundation/layout/BoxChildDataElement;

    .line 2
    .line 3
    sget-object v0, Lx2/c;->h:Lx2/j;

    .line 4
    .line 5
    const/4 v1, 0x1

    .line 6
    invoke-direct {p0, v0, v1}, Landroidx/compose/foundation/layout/BoxChildDataElement;-><init>(Lx2/e;Z)V

    .line 7
    .line 8
    .line 9
    return-object p0
.end method
