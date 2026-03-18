.class public Lcom/google/android/libraries/barhopper/RecognitionOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
    value = "jni_common.cc"
.end annotation


# instance fields
.field private barcodeFormats:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private enableQrAlignmentGrid:Z
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private enableUseKeypointAsFinderPattern:Z
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private multiScaleDecodingOptions:Lcom/google/android/libraries/barhopper/MultiScaleDecodingOptions;
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private multiScaleDetectionOptions:Lcom/google/android/libraries/barhopper/MultiScaleDetectionOptions;
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private onedRecognitionOptions:Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private outputUnrecognizedBarcodes:Z
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private qrEnableFourthCornerApproximation:Z
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private useHalideAffineCrop:Z
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private useQrMobilenetV3:Z
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x0

    .line 5
    iput v0, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->barcodeFormats:I

    .line 6
    .line 7
    iput-boolean v0, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->outputUnrecognizedBarcodes:Z

    .line 8
    .line 9
    iput-boolean v0, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->useQrMobilenetV3:Z

    .line 10
    .line 11
    const/4 v1, 0x1

    .line 12
    iput-boolean v1, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->enableQrAlignmentGrid:Z

    .line 13
    .line 14
    iput-boolean v1, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->enableUseKeypointAsFinderPattern:Z

    .line 15
    .line 16
    iput-boolean v0, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->useHalideAffineCrop:Z

    .line 17
    .line 18
    new-instance v1, Lcom/google/android/libraries/barhopper/MultiScaleDecodingOptions;

    .line 19
    .line 20
    invoke-direct {v1}, Lcom/google/android/libraries/barhopper/MultiScaleDecodingOptions;-><init>()V

    .line 21
    .line 22
    .line 23
    iput-object v1, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->multiScaleDecodingOptions:Lcom/google/android/libraries/barhopper/MultiScaleDecodingOptions;

    .line 24
    .line 25
    new-instance v1, Lcom/google/android/libraries/barhopper/MultiScaleDetectionOptions;

    .line 26
    .line 27
    invoke-direct {v1}, Lcom/google/android/libraries/barhopper/MultiScaleDetectionOptions;-><init>()V

    .line 28
    .line 29
    .line 30
    iput-object v1, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->multiScaleDetectionOptions:Lcom/google/android/libraries/barhopper/MultiScaleDetectionOptions;

    .line 31
    .line 32
    new-instance v1, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;

    .line 33
    .line 34
    invoke-direct {v1}, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;-><init>()V

    .line 35
    .line 36
    .line 37
    iput-object v1, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->onedRecognitionOptions:Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;

    .line 38
    .line 39
    iput-boolean v0, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->qrEnableFourthCornerApproximation:Z

    .line 40
    .line 41
    return-void
.end method


# virtual methods
.method public final a(I)V
    .locals 0

    .line 1
    iput p1, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->barcodeFormats:I

    .line 2
    .line 3
    return-void
.end method

.method public final b()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->enableQrAlignmentGrid:Z

    .line 3
    .line 4
    return-void
.end method

.method public final c()V
    .locals 1

    .line 1
    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->enableUseKeypointAsFinderPattern:Z

    .line 3
    .line 4
    return-void
.end method

.method public final d(Lcom/google/android/libraries/barhopper/MultiScaleDecodingOptions;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->multiScaleDecodingOptions:Lcom/google/android/libraries/barhopper/MultiScaleDecodingOptions;

    .line 2
    .line 3
    return-void
.end method

.method public final e(Lcom/google/android/libraries/barhopper/MultiScaleDetectionOptions;)V
    .locals 0

    .line 1
    iput-object p1, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->multiScaleDetectionOptions:Lcom/google/android/libraries/barhopper/MultiScaleDetectionOptions;

    .line 2
    .line 3
    return-void
.end method

.method public final f(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->outputUnrecognizedBarcodes:Z

    .line 2
    .line 3
    return-void
.end method

.method public final g(Z)V
    .locals 0

    .line 1
    iput-boolean p1, p0, Lcom/google/android/libraries/barhopper/RecognitionOptions;->qrEnableFourthCornerApproximation:Z

    .line 2
    .line 3
    return-void
.end method
