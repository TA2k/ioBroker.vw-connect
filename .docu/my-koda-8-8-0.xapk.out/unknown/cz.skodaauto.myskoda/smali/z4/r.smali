.class public abstract Lz4/r;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic a:[Lhy0/z;

.field public static final b:Ld4/z;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Lkotlin/jvm/internal/r;

    .line 2
    .line 3
    const-class v1, Lz4/r;

    .line 4
    .line 5
    const-string v2, "designInfoProvider"

    .line 6
    .line 7
    const-string v3, "getDesignInfoProvider(Landroidx/compose/ui/semantics/SemanticsPropertyReceiver;)Landroidx/constraintlayout/compose/DesignInfoProvider;"

    .line 8
    .line 9
    const/4 v4, 0x1

    .line 10
    invoke-direct {v0, v1, v2, v3, v4}, Lkotlin/jvm/internal/r;-><init>(Ljava/lang/Class;Ljava/lang/String;Ljava/lang/String;I)V

    .line 11
    .line 12
    .line 13
    sget-object v1, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 14
    .line 15
    invoke-virtual {v1, v0}, Lkotlin/jvm/internal/h0;->mutableProperty1(Lkotlin/jvm/internal/q;)Lhy0/l;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    new-array v1, v4, [Lhy0/z;

    .line 20
    .line 21
    const/4 v2, 0x0

    .line 22
    aput-object v0, v1, v2

    .line 23
    .line 24
    sput-object v1, Lz4/r;->a:[Lhy0/z;

    .line 25
    .line 26
    new-instance v0, Ld4/z;

    .line 27
    .line 28
    const-string v1, "DesignInfoProvider"

    .line 29
    .line 30
    invoke-direct {v0, v1}, Ld4/z;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    sput-object v0, Lz4/r;->b:Ld4/z;

    .line 34
    .line 35
    return-void
.end method

.method public static final a(Ld4/l;Lz4/p;)V
    .locals 2

    .line 1
    sget-object v0, Lz4/r;->a:[Lhy0/z;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    aget-object v0, v0, v1

    .line 5
    .line 6
    sget-object v0, Lz4/r;->b:Ld4/z;

    .line 7
    .line 8
    invoke-virtual {v0, p0, p1}, Ld4/z;->a(Ld4/l;Ljava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method
