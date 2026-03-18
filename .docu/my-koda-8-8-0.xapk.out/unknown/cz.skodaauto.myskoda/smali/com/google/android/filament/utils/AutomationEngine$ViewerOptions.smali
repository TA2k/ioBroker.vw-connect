.class public Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/utils/AutomationEngine;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "ViewerOptions"
.end annotation


# instance fields
.field public autoInstancingEnabled:Z

.field public autoScaleEnabled:Z

.field public cameraAperture:F

.field public cameraFar:F

.field public cameraFocalLength:F

.field public cameraFocusDistance:F

.field public cameraISO:F

.field public cameraNear:F

.field public cameraSpeed:F

.field public groundPlaneEnabled:Z

.field public groundShadowStrength:F

.field public skyboxEnabled:Z


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/high16 v0, 0x41800000    # 16.0f

    .line 5
    .line 6
    iput v0, p0, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;->cameraAperture:F

    .line 7
    .line 8
    const/high16 v0, 0x42fa0000    # 125.0f

    .line 9
    .line 10
    iput v0, p0, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;->cameraSpeed:F

    .line 11
    .line 12
    const/high16 v0, 0x42c80000    # 100.0f

    .line 13
    .line 14
    iput v0, p0, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;->cameraISO:F

    .line 15
    .line 16
    const v1, 0x3dcccccd    # 0.1f

    .line 17
    .line 18
    .line 19
    iput v1, p0, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;->cameraNear:F

    .line 20
    .line 21
    iput v0, p0, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;->cameraFar:F

    .line 22
    .line 23
    const/high16 v0, 0x3f400000    # 0.75f

    .line 24
    .line 25
    iput v0, p0, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;->groundShadowStrength:F

    .line 26
    .line 27
    const/4 v0, 0x0

    .line 28
    iput-boolean v0, p0, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;->groundPlaneEnabled:Z

    .line 29
    .line 30
    const/4 v1, 0x1

    .line 31
    iput-boolean v1, p0, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;->skyboxEnabled:Z

    .line 32
    .line 33
    const/high16 v2, 0x41e00000    # 28.0f

    .line 34
    .line 35
    iput v2, p0, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;->cameraFocalLength:F

    .line 36
    .line 37
    const/4 v2, 0x0

    .line 38
    iput v2, p0, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;->cameraFocusDistance:F

    .line 39
    .line 40
    iput-boolean v1, p0, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;->autoScaleEnabled:Z

    .line 41
    .line 42
    iput-boolean v0, p0, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;->autoInstancingEnabled:Z

    .line 43
    .line 44
    return-void
.end method
