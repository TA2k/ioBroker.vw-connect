.class public final Lcom/google/android/libraries/barhopper/MultiScaleDecodingOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
    value = "jni_common.cc"
.end annotation


# instance fields
.field private extraScales:[F
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private minimumDetectedDimension:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private skipProcessingIfBarcodeFound:Z
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    new-array v0, v0, [F

    .line 6
    .line 7
    iput-object v0, p0, Lcom/google/android/libraries/barhopper/MultiScaleDecodingOptions;->extraScales:[F

    .line 8
    .line 9
    const/16 v0, 0xa

    .line 10
    .line 11
    iput v0, p0, Lcom/google/android/libraries/barhopper/MultiScaleDecodingOptions;->minimumDetectedDimension:I

    .line 12
    .line 13
    const/4 v0, 0x1

    .line 14
    iput-boolean v0, p0, Lcom/google/android/libraries/barhopper/MultiScaleDecodingOptions;->skipProcessingIfBarcodeFound:Z

    .line 15
    .line 16
    return-void
.end method


# virtual methods
.method public final a([F)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/libraries/barhopper/MultiScaleDecodingOptions;->extraScales:[F

    .line 2
    .line 3
    return-void
.end method

.method public final b(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/libraries/barhopper/MultiScaleDecodingOptions;->minimumDetectedDimension:I

    .line 2
    .line 3
    return-void
.end method

.method public final c(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/google/android/libraries/barhopper/MultiScaleDecodingOptions;->skipProcessingIfBarcodeFound:Z

    .line 2
    .line 3
    return-void
.end method
