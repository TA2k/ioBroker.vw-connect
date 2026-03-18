.class final Landroidx/compose/foundation/IndicationModifierElement;
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
        "\u0000\u000e\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u0008\u0002\u0018\u00002\u0008\u0012\u0004\u0012\u00020\u00020\u0001\u00a8\u0006\u0003"
    }
    d2 = {
        "Landroidx/compose/foundation/IndicationModifierElement;",
        "Lv3/z0;",
        "Le1/r0;",
        "foundation_release"
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
.field public final b:Li1/l;

.field public final c:Le1/s0;


# direct methods
.method public constructor <init>(Li1/l;Le1/s0;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Landroidx/compose/foundation/IndicationModifierElement;->b:Li1/l;

    .line 5
    .line 6
    iput-object p2, p0, Landroidx/compose/foundation/IndicationModifierElement;->c:Le1/s0;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Landroidx/compose/foundation/IndicationModifierElement;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Landroidx/compose/foundation/IndicationModifierElement;

    .line 12
    .line 13
    iget-object v1, p1, Landroidx/compose/foundation/IndicationModifierElement;->b:Li1/l;

    .line 14
    .line 15
    iget-object v3, p0, Landroidx/compose/foundation/IndicationModifierElement;->b:Li1/l;

    .line 16
    .line 17
    invoke-static {v3, v1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object p0, p0, Landroidx/compose/foundation/IndicationModifierElement;->c:Le1/s0;

    .line 25
    .line 26
    iget-object p1, p1, Landroidx/compose/foundation/IndicationModifierElement;->c:Le1/s0;

    .line 27
    .line 28
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-nez p0, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    return v0
.end method

.method public final h()Lx2/r;
    .locals 2

    .line 1
    new-instance v0, Le1/r0;

    .line 2
    .line 3
    iget-object v1, p0, Landroidx/compose/foundation/IndicationModifierElement;->c:Le1/s0;

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/compose/foundation/IndicationModifierElement;->b:Li1/l;

    .line 6
    .line 7
    invoke-interface {v1, p0}, Le1/s0;->a(Li1/l;)Lv3/m;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    invoke-direct {v0}, Lv3/n;-><init>()V

    .line 12
    .line 13
    .line 14
    iput-object p0, v0, Le1/r0;->t:Lv3/m;

    .line 15
    .line 16
    invoke-virtual {v0, p0}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 17
    .line 18
    .line 19
    return-object v0
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Landroidx/compose/foundation/IndicationModifierElement;->b:Li1/l;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object p0, p0, Landroidx/compose/foundation/IndicationModifierElement;->c:Le1/s0;

    .line 10
    .line 11
    invoke-interface {p0}, Le1/s0;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public final j(Lx2/r;)V
    .locals 1

    .line 1
    check-cast p1, Le1/r0;

    .line 2
    .line 3
    iget-object v0, p0, Landroidx/compose/foundation/IndicationModifierElement;->c:Le1/s0;

    .line 4
    .line 5
    iget-object p0, p0, Landroidx/compose/foundation/IndicationModifierElement;->b:Li1/l;

    .line 6
    .line 7
    invoke-interface {v0, p0}, Le1/s0;->a(Li1/l;)Lv3/m;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    iget-object v0, p1, Le1/r0;->t:Lv3/m;

    .line 12
    .line 13
    invoke-virtual {p1, v0}, Lv3/n;->Y0(Lv3/m;)V

    .line 14
    .line 15
    .line 16
    iput-object p0, p1, Le1/r0;->t:Lv3/m;

    .line 17
    .line 18
    invoke-virtual {p1, p0}, Lv3/n;->X0(Lv3/m;)Lv3/m;

    .line 19
    .line 20
    .line 21
    return-void
.end method
