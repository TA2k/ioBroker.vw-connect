.class public abstract Lv3/k0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lt4/d;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lkp/b9;->a()Lt4/d;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lv3/k0;->a:Lt4/d;

    .line 6
    .line 7
    return-void
.end method

.method public static final a(Lv3/h0;)Lv3/o1;
    .locals 0

    .line 1
    iget-object p0, p0, Lv3/h0;->p:Lv3/o1;

    .line 2
    .line 3
    if-eqz p0, :cond_0

    .line 4
    .line 5
    return-object p0

    .line 6
    :cond_0
    const-string p0, "LayoutNode should be attached to an owner"

    .line 7
    .line 8
    invoke-static {p0}, Lvj/b;->b(Ljava/lang/String;)La8/r0;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    throw p0
.end method
