.class public final Landroidx/compose/ui/CompositionLocalMapInjectionElement;
.super Lv3/z0;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/Signature;
    value = {
        "Lv3/z0;"
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0001\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/ui/CompositionLocalMapInjectionElement;",
        "Lv3/z0;",
        "Lx2/o;",
        "ui_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field public final b:Ll2/c0;


# direct methods
.method public constructor <init>(Ll2/p1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/ui/CompositionLocalMapInjectionElement;->b:Ll2/c0;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 1

    .line 1
    instance-of v0, p1, Landroidx/compose/ui/CompositionLocalMapInjectionElement;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    check-cast p1, Landroidx/compose/ui/CompositionLocalMapInjectionElement;

    .line 6
    .line 7
    iget-object p1, p1, Landroidx/compose/ui/CompositionLocalMapInjectionElement;->b:Ll2/c0;

    .line 8
    .line 9
    iget-object p0, p0, Landroidx/compose/ui/CompositionLocalMapInjectionElement;->b:Ll2/c0;

    .line 10
    .line 11
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    if-eqz p0, :cond_0

    .line 16
    .line 17
    const/4 p0, 0x1

    .line 18
    return p0

    .line 19
    :cond_0
    const/4 p0, 0x0

    .line 20
    return p0
.end method

.method public final h()Lx2/r;
    .locals 1

    .line 1
    new-instance v0, Lx2/o;

    .line 2
    .line 3
    invoke-direct {v0}, Lx2/r;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Landroidx/compose/ui/CompositionLocalMapInjectionElement;->b:Ll2/c0;

    .line 7
    .line 8
    iput-object p0, v0, Lx2/o;->r:Ll2/c0;

    .line 9
    .line 10
    return-object v0
.end method

.method public final hashCode()I
    .locals 0

    .line 1
    iget-object p0, p0, Landroidx/compose/ui/CompositionLocalMapInjectionElement;->b:Ll2/c0;

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public final j(Lx2/r;)V
    .locals 0

    .line 1
    check-cast p1, Lx2/o;

    .line 2
    .line 3
    iget-object p0, p0, Landroidx/compose/ui/CompositionLocalMapInjectionElement;->b:Ll2/c0;

    .line 4
    .line 5
    iput-object p0, p1, Lx2/o;->r:Ll2/c0;

    .line 6
    .line 7
    invoke-static {p1}, Lv3/f;->x(Lv3/m;)Lv3/h0;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    invoke-virtual {p1, p0}, Lv3/h0;->c0(Ll2/c0;)V

    .line 12
    .line 13
    .line 14
    return-void
.end method
