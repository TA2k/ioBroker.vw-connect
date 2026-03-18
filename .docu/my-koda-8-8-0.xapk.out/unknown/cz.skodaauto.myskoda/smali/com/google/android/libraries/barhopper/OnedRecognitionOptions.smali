.class public Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
    value = "jni_common.cc"
.end annotation


# instance fields
.field private codabarMinCodeLength:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private codabarMinConsistentLines:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private code128MinCodeLength:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private code128MinConsistentLines:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private code39MinCodeLength:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private code39MinConsistentLines:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private code39UseCheckDigit:Z
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private code39UseExtendedMode:Z
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private code93MinCodeLength:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private code93MinConsistentLines:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private ean13UpcaMinConsistentLines:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private ean8MinConsistentLines:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private itfMinCodeLength:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private itfMinConsistentLines:I
    .annotation build Lcom/google/android/apps/common/proguard/UsedByNative;
        value = "jni_common.cc"
    .end annotation
.end field

.field private upceMinConsistentLines:I
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
    const/4 v0, 0x1

    .line 5
    iput v0, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->ean13UpcaMinConsistentLines:I

    .line 6
    .line 7
    const/4 v1, 0x3

    .line 8
    iput v1, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->ean8MinConsistentLines:I

    .line 9
    .line 10
    iput v1, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->upceMinConsistentLines:I

    .line 11
    .line 12
    iput v0, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->code128MinConsistentLines:I

    .line 13
    .line 14
    const/4 v0, 0x2

    .line 15
    iput v0, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->code39MinConsistentLines:I

    .line 16
    .line 17
    iput v0, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->code93MinConsistentLines:I

    .line 18
    .line 19
    iput v1, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->itfMinConsistentLines:I

    .line 20
    .line 21
    iput v0, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->codabarMinConsistentLines:I

    .line 22
    .line 23
    iput v0, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->code128MinCodeLength:I

    .line 24
    .line 25
    iput v0, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->code39MinCodeLength:I

    .line 26
    .line 27
    iput v0, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->code93MinCodeLength:I

    .line 28
    .line 29
    const/4 v0, 0x6

    .line 30
    iput v0, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->itfMinCodeLength:I

    .line 31
    .line 32
    iput v0, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->codabarMinCodeLength:I

    .line 33
    .line 34
    const/4 v0, 0x0

    .line 35
    iput-boolean v0, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->code39UseCheckDigit:Z

    .line 36
    .line 37
    iput-boolean v0, p0, Lcom/google/android/libraries/barhopper/OnedRecognitionOptions;->code39UseExtendedMode:Z

    .line 38
    .line 39
    return-void
.end method
