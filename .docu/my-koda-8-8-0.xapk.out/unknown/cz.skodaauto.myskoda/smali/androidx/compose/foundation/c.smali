.class public abstract Landroidx/compose/foundation/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ll2/e0;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ldc/a;

    .line 2
    .line 3
    const/16 v1, 0xf

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ldc/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    new-instance v1, Ll2/e0;

    .line 9
    .line 10
    invoke-direct {v1, v0}, Ll2/e0;-><init>(Lay0/a;)V

    .line 11
    .line 12
    .line 13
    sput-object v1, Landroidx/compose/foundation/c;->a:Ll2/e0;

    .line 14
    .line 15
    return-void
.end method

.method public static final a(Li1/l;Le1/s0;)Lx2/s;
    .locals 1

    .line 1
    if-nez p1, :cond_0

    .line 2
    .line 3
    sget-object p0, Lx2/p;->b:Lx2/p;

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    new-instance v0, Landroidx/compose/foundation/IndicationModifierElement;

    .line 7
    .line 8
    invoke-direct {v0, p0, p1}, Landroidx/compose/foundation/IndicationModifierElement;-><init>(Li1/l;Le1/s0;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method
