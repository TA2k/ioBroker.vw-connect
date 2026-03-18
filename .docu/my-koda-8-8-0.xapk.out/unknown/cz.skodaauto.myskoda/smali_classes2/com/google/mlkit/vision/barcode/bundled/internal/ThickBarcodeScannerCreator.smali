.class public Lcom/google/mlkit/vision/barcode/bundled/internal/ThickBarcodeScannerCreator;
.super Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/z;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation build Lcom/google/android/gms/common/util/DynamiteApi;
.end annotation


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    const-string v0, "com.google.mlkit.vision.barcode.aidls.IBarcodeScannerCreator"

    .line 2
    .line 3
    invoke-direct {p0, v0}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/t;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public newBarcodeScanner(Lyo/a;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u;)Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/x;
    .locals 0

    .line 1
    new-instance p0, Liv/a;

    .line 2
    .line 3
    invoke-static {p1}, Lyo/b;->U(Lyo/a;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    check-cast p1, Landroid/content/Context;

    .line 8
    .line 9
    invoke-direct {p0, p1, p2}, Liv/a;-><init>(Landroid/content/Context;Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/u;)V

    .line 10
    .line 11
    .line 12
    return-object p0
.end method
