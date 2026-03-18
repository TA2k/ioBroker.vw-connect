.class public Landroidx/camera/camera2/internal/compat/quirk/FlashTooSlowQuirk;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroidx/camera/camera2/internal/compat/quirk/UseTorchAsFlashQuirk;


# static fields
.field public static final a:Ljava/util/List;


# direct methods
.method static constructor <clinit>()V
    .locals 8

    .line 1
    const-string v6, "ITEL L6006"

    .line 2
    .line 3
    const-string v7, "RMX3231"

    .line 4
    .line 5
    const-string v0, "PIXEL 3A"

    .line 6
    .line 7
    const-string v1, "PIXEL 3A XL"

    .line 8
    .line 9
    const-string v2, "PIXEL 4"

    .line 10
    .line 11
    const-string v3, "PIXEL 5"

    .line 12
    .line 13
    const-string v4, "SM-A320"

    .line 14
    .line 15
    const-string v5, "MOTO G(20)"

    .line 16
    .line 17
    filled-new-array/range {v0 .. v7}, [Ljava/lang/String;

    .line 18
    .line 19
    .line 20
    move-result-object v0

    .line 21
    invoke-static {v0}, Ljava/util/Arrays;->asList([Ljava/lang/Object;)Ljava/util/List;

    .line 22
    .line 23
    .line 24
    move-result-object v0

    .line 25
    sput-object v0, Landroidx/camera/camera2/internal/compat/quirk/FlashTooSlowQuirk;->a:Ljava/util/List;

    .line 26
    .line 27
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
