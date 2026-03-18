.class public Landroidx/camera/camera2/internal/compat/quirk/TorchIsClosedAfterImageCapturingQuirk;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lh0/p1;


# static fields
.field public static final a:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 9

    .line 1
    const-string v7, "redmi 6 pro"

    .line 2
    .line 3
    const-string v8, "redmi note 6 pro"

    .line 4
    .line 5
    const-string v0, "mi a1"

    .line 6
    .line 7
    const-string v1, "mi a2"

    .line 8
    .line 9
    const-string v2, "mi a2 lite"

    .line 10
    .line 11
    const-string v3, "redmi 4x"

    .line 12
    .line 13
    const-string v4, "redmi 5a"

    .line 14
    .line 15
    const-string v5, "redmi note 5"

    .line 16
    .line 17
    const-string v6, "redmi note 5 pro"

    .line 18
    .line 19
    filled-new-array/range {v0 .. v8}, [Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 24
    .line 25
    .line 26
    move-result-object v0

    .line 27
    sput-object v0, Landroidx/camera/camera2/internal/compat/quirk/TorchIsClosedAfterImageCapturingQuirk;->a:Ljava/util/List;

    .line 28
    .line 29
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
