.class public final Lcom/google/android/filament/utils/Half$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/utils/Half;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u001c\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0015\u0010\u001f\u001a\u00020\u00072\u0006\u0010 \u001a\u00020\u0005\u00a2\u0006\u0004\u0008!\u0010\"R\u000e\u0010\u0004\u001a\u00020\u0005X\u0086T\u00a2\u0006\u0002\n\u0000R\u0013\u0010\u0006\u001a\u00020\u0007\u00a2\u0006\n\n\u0002\u0010\n\u001a\u0004\u0008\u0008\u0010\tR\u000e\u0010\u000b\u001a\u00020\u0005X\u0086T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u000c\u001a\u00020\u0005X\u0086T\u00a2\u0006\u0002\n\u0000R\u0013\u0010\r\u001a\u00020\u0007\u00a2\u0006\n\n\u0002\u0010\n\u001a\u0004\u0008\u000e\u0010\tR\u0013\u0010\u000f\u001a\u00020\u0007\u00a2\u0006\n\n\u0002\u0010\n\u001a\u0004\u0008\u0010\u0010\tR\u0013\u0010\u0011\u001a\u00020\u0007\u00a2\u0006\n\n\u0002\u0010\n\u001a\u0004\u0008\u0012\u0010\tR\u0013\u0010\u0013\u001a\u00020\u0007\u00a2\u0006\n\n\u0002\u0010\n\u001a\u0004\u0008\u0014\u0010\tR\u0013\u0010\u0015\u001a\u00020\u0007\u00a2\u0006\n\n\u0002\u0010\n\u001a\u0004\u0008\u0016\u0010\tR\u0013\u0010\u0017\u001a\u00020\u0007\u00a2\u0006\n\n\u0002\u0010\n\u001a\u0004\u0008\u0018\u0010\tR\u0013\u0010\u0019\u001a\u00020\u0007\u00a2\u0006\n\n\u0002\u0010\n\u001a\u0004\u0008\u001a\u0010\tR\u0013\u0010\u001b\u001a\u00020\u0007\u00a2\u0006\n\n\u0002\u0010\n\u001a\u0004\u0008\u001c\u0010\tR\u0013\u0010\u001d\u001a\u00020\u0007\u00a2\u0006\n\n\u0002\u0010\n\u001a\u0004\u0008\u001e\u0010\t\u00a8\u0006#"
    }
    d2 = {
        "Lcom/google/android/filament/utils/Half$Companion;",
        "",
        "<init>",
        "()V",
        "SIZE",
        "",
        "EPSILON",
        "Lcom/google/android/filament/utils/Half;",
        "getEPSILON-SjiOe_E",
        "()S",
        "S",
        "MAX_EXPONENT",
        "MIN_EXPONENT",
        "LOWEST_VALUE",
        "getLOWEST_VALUE-SjiOe_E",
        "MAX_VALUE",
        "getMAX_VALUE-SjiOe_E",
        "MIN_NORMAL",
        "getMIN_NORMAL-SjiOe_E",
        "MIN_VALUE",
        "getMIN_VALUE-SjiOe_E",
        "NaN",
        "getNaN-SjiOe_E",
        "NEGATIVE_INFINITY",
        "getNEGATIVE_INFINITY-SjiOe_E",
        "NEGATIVE_ZERO",
        "getNEGATIVE_ZERO-SjiOe_E",
        "POSITIVE_INFINITY",
        "getPOSITIVE_INFINITY-SjiOe_E",
        "POSITIVE_ZERO",
        "getPOSITIVE_ZERO-SjiOe_E",
        "fromBits",
        "bits",
        "fromBits-YoEgL-c",
        "(I)S",
        "filament-utils-android_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcom/google/android/filament/utils/Half$Companion;-><init>()V

    return-void
.end method


# virtual methods
.method public final fromBits-YoEgL-c(I)S
    .locals 0

    .line 1
    const p0, 0xffff

    .line 2
    .line 3
    .line 4
    and-int/2addr p0, p1

    .line 5
    int-to-short p0, p0

    .line 6
    invoke-static {p0}, Lcom/google/android/filament/utils/Half;->constructor-impl(S)S

    .line 7
    .line 8
    .line 9
    move-result p0

    .line 10
    return p0
.end method

.method public final getEPSILON-SjiOe_E()S
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/android/filament/utils/Half;->access$getEPSILON$cp()S

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final getLOWEST_VALUE-SjiOe_E()S
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/android/filament/utils/Half;->access$getLOWEST_VALUE$cp()S

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final getMAX_VALUE-SjiOe_E()S
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/android/filament/utils/Half;->access$getMAX_VALUE$cp()S

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final getMIN_NORMAL-SjiOe_E()S
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/android/filament/utils/Half;->access$getMIN_NORMAL$cp()S

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final getMIN_VALUE-SjiOe_E()S
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/android/filament/utils/Half;->access$getMIN_VALUE$cp()S

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final getNEGATIVE_INFINITY-SjiOe_E()S
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/android/filament/utils/Half;->access$getNEGATIVE_INFINITY$cp()S

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final getNEGATIVE_ZERO-SjiOe_E()S
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/android/filament/utils/Half;->access$getNEGATIVE_ZERO$cp()S

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final getNaN-SjiOe_E()S
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/android/filament/utils/Half;->access$getNaN$cp()S

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final getPOSITIVE_INFINITY-SjiOe_E()S
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/android/filament/utils/Half;->access$getPOSITIVE_INFINITY$cp()S

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method

.method public final getPOSITIVE_ZERO-SjiOe_E()S
    .locals 0

    .line 1
    invoke-static {}, Lcom/google/android/filament/utils/Half;->access$getPOSITIVE_ZERO$cp()S

    .line 2
    .line 3
    .line 4
    move-result p0

    .line 5
    return p0
.end method
