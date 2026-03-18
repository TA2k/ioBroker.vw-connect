.class public abstract Landroidx/compose/foundation/text/handwriting/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lv3/o;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    const/16 v0, 0x28

    .line 2
    .line 3
    int-to-float v0, v0

    .line 4
    const/16 v1, 0xa

    .line 5
    .line 6
    int-to-float v1, v1

    .line 7
    new-instance v2, Lv3/o;

    .line 8
    .line 9
    invoke-direct {v2, v1, v0, v1, v0}, Lv3/o;-><init>(FFFF)V

    .line 10
    .line 11
    .line 12
    sput-object v2, Landroidx/compose/foundation/text/handwriting/a;->a:Lv3/o;

    .line 13
    .line 14
    return-void
.end method

.method public static final a(Lay0/a;ZZ)Lx2/s;
    .locals 1

    .line 1
    sget-object v0, Lx2/p;->b:Lx2/p;

    .line 2
    .line 3
    if-eqz p1, :cond_1

    .line 4
    .line 5
    sget-boolean p1, Lb2/d;->a:Z

    .line 6
    .line 7
    if-eqz p1, :cond_1

    .line 8
    .line 9
    if-eqz p2, :cond_0

    .line 10
    .line 11
    new-instance v0, Landroidx/compose/ui/input/pointer/StylusHoverIconModifierElement;

    .line 12
    .line 13
    sget-object p1, Landroidx/compose/foundation/text/handwriting/a;->a:Lv3/o;

    .line 14
    .line 15
    invoke-direct {v0, p1}, Landroidx/compose/ui/input/pointer/StylusHoverIconModifierElement;-><init>(Lv3/o;)V

    .line 16
    .line 17
    .line 18
    :cond_0
    new-instance p1, Landroidx/compose/foundation/text/handwriting/StylusHandwritingElement;

    .line 19
    .line 20
    invoke-direct {p1, p0}, Landroidx/compose/foundation/text/handwriting/StylusHandwritingElement;-><init>(Lay0/a;)V

    .line 21
    .line 22
    .line 23
    invoke-interface {v0, p1}, Lx2/s;->g(Lx2/s;)Lx2/s;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0

    .line 28
    :cond_1
    return-object v0
.end method
