.class public Lcom/google/android/filament/View$FogOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/View;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "FogOptions"
.end annotation


# instance fields
.field public color:[F

.field public cutOffDistance:F

.field public density:F

.field public distance:F

.field public enabled:Z

.field public fogColorFromIbl:Z

.field public height:F

.field public heightFalloff:F

.field public inScatteringSize:F

.field public inScatteringStart:F

.field public maximumOpacity:F

.field public skyColor:Lcom/google/android/filament/Texture;


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
    iput v0, p0, Lcom/google/android/filament/View$FogOptions;->distance:F

    .line 6
    .line 7
    const/high16 v1, 0x7f800000    # Float.POSITIVE_INFINITY

    .line 8
    .line 9
    iput v1, p0, Lcom/google/android/filament/View$FogOptions;->cutOffDistance:F

    .line 10
    .line 11
    const/high16 v1, 0x3f800000    # 1.0f

    .line 12
    .line 13
    iput v1, p0, Lcom/google/android/filament/View$FogOptions;->maximumOpacity:F

    .line 14
    .line 15
    iput v0, p0, Lcom/google/android/filament/View$FogOptions;->height:F

    .line 16
    .line 17
    iput v1, p0, Lcom/google/android/filament/View$FogOptions;->heightFalloff:F

    .line 18
    .line 19
    const/4 v1, 0x3

    .line 20
    new-array v1, v1, [F

    .line 21
    .line 22
    fill-array-data v1, :array_0

    .line 23
    .line 24
    .line 25
    iput-object v1, p0, Lcom/google/android/filament/View$FogOptions;->color:[F

    .line 26
    .line 27
    const v1, 0x3dcccccd    # 0.1f

    .line 28
    .line 29
    .line 30
    iput v1, p0, Lcom/google/android/filament/View$FogOptions;->density:F

    .line 31
    .line 32
    iput v0, p0, Lcom/google/android/filament/View$FogOptions;->inScatteringStart:F

    .line 33
    .line 34
    const/high16 v0, -0x40800000    # -1.0f

    .line 35
    .line 36
    iput v0, p0, Lcom/google/android/filament/View$FogOptions;->inScatteringSize:F

    .line 37
    .line 38
    const/4 v0, 0x0

    .line 39
    iput-boolean v0, p0, Lcom/google/android/filament/View$FogOptions;->fogColorFromIbl:Z

    .line 40
    .line 41
    const/4 v1, 0x0

    .line 42
    iput-object v1, p0, Lcom/google/android/filament/View$FogOptions;->skyColor:Lcom/google/android/filament/Texture;

    .line 43
    .line 44
    iput-boolean v0, p0, Lcom/google/android/filament/View$FogOptions;->enabled:Z

    .line 45
    .line 46
    return-void

    .line 47
    :array_0
    .array-data 4
        0x3f800000    # 1.0f
        0x3f800000    # 1.0f
        0x3f800000    # 1.0f
    .end array-data
.end method
