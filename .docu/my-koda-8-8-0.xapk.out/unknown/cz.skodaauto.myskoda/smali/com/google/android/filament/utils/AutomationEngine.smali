.class public Lcom/google/android/filament/utils/AutomationEngine;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/AutomationEngine$Options;,
        Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;,
        Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;
    }
.end annotation


# instance fields
.field private mColorGrading:Lcom/google/android/filament/ColorGrading;

.field private final mNativeObject:J


# direct methods
.method public constructor <init>()V
    .locals 4

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    invoke-static {}, Lcom/google/android/filament/utils/AutomationEngine;->nCreateDefaultAutomationEngine()J

    move-result-wide v0

    iput-wide v0, p0, Lcom/google/android/filament/utils/AutomationEngine;->mNativeObject:J

    const-wide/16 v2, 0x0

    cmp-long p0, v0, v2

    if-eqz p0, :cond_0

    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string v0, "Couldn\'t create AutomationEngine"

    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    invoke-static {p1}, Lcom/google/android/filament/utils/AutomationEngine;->nCreateAutomationEngine(Ljava/lang/String;)J

    move-result-wide v0

    iput-wide v0, p0, Lcom/google/android/filament/utils/AutomationEngine;->mNativeObject:J

    const-wide/16 p0, 0x0

    cmp-long p0, v0, p0

    if-eqz p0, :cond_0

    return-void

    .line 3
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    const-string p1, "Couldn\'t create AutomationEngine"

    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method private static native nApplySettings(JJLjava/lang/String;J[JJI[IJJJ)V
.end method

.method private static native nCreateAutomationEngine(Ljava/lang/String;)J
.end method

.method private static native nCreateDefaultAutomationEngine()J
.end method

.method private static native nDestroy(J)V
.end method

.method private static native nGetColorGrading(JJ)J
.end method

.method private static native nGetViewerOptions(JLjava/lang/Object;)V
.end method

.method private static native nSetOptions(JFIZ)V
.end method

.method private static native nShouldClose(J)Z
.end method

.method private static native nSignalBatchMode(J)V
.end method

.method private static native nStartBatchMode(J)V
.end method

.method private static native nStartRunning(J)V
.end method

.method private static native nStopRunning(J)V
.end method

.method private static native nTick(JJJ[JJF)V
.end method


# virtual methods
.method public applySettings(Lcom/google/android/filament/Engine;Ljava/lang/String;Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;)V
    .locals 21

    .line 1
    move-object/from16 v0, p3

    .line 2
    .line 3
    iget-object v1, v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->view:Lcom/google/android/filament/View;

    .line 4
    .line 5
    if-eqz v1, :cond_4

    .line 6
    .line 7
    iget-object v1, v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->renderer:Lcom/google/android/filament/Renderer;

    .line 8
    .line 9
    if-eqz v1, :cond_4

    .line 10
    .line 11
    iget-object v1, v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->lightManager:Lcom/google/android/filament/LightManager;

    .line 12
    .line 13
    if-eqz v1, :cond_3

    .line 14
    .line 15
    iget-object v1, v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->scene:Lcom/google/android/filament/Scene;

    .line 16
    .line 17
    if-eqz v1, :cond_3

    .line 18
    .line 19
    iget-object v1, v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->materials:[Lcom/google/android/filament/MaterialInstance;

    .line 20
    .line 21
    if-eqz v1, :cond_1

    .line 22
    .line 23
    array-length v1, v1

    .line 24
    new-array v2, v1, [J

    .line 25
    .line 26
    const/4 v3, 0x0

    .line 27
    :goto_0
    if-ge v3, v1, :cond_0

    .line 28
    .line 29
    iget-object v4, v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->materials:[Lcom/google/android/filament/MaterialInstance;

    .line 30
    .line 31
    aget-object v4, v4, v3

    .line 32
    .line 33
    invoke-virtual {v4}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 34
    .line 35
    .line 36
    move-result-wide v4

    .line 37
    aput-wide v4, v2, v3

    .line 38
    .line 39
    add-int/lit8 v3, v3, 0x1

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    :goto_1
    move-object v10, v2

    .line 43
    goto :goto_2

    .line 44
    :cond_1
    const/4 v2, 0x0

    .line 45
    goto :goto_1

    .line 46
    :goto_2
    iget-object v1, v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->view:Lcom/google/android/filament/View;

    .line 47
    .line 48
    invoke-virtual {v1}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 49
    .line 50
    .line 51
    move-result-wide v8

    .line 52
    iget-object v1, v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->indirectLight:Lcom/google/android/filament/IndirectLight;

    .line 53
    .line 54
    if-nez v1, :cond_2

    .line 55
    .line 56
    const-wide/16 v1, 0x0

    .line 57
    .line 58
    :goto_3
    move-wide v11, v1

    .line 59
    goto :goto_4

    .line 60
    :cond_2
    invoke-virtual {v1}, Lcom/google/android/filament/IndirectLight;->getNativeObject()J

    .line 61
    .line 62
    .line 63
    move-result-wide v1

    .line 64
    goto :goto_3

    .line 65
    :goto_4
    iget-object v1, v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->lightManager:Lcom/google/android/filament/LightManager;

    .line 66
    .line 67
    invoke-virtual {v1}, Lcom/google/android/filament/LightManager;->getNativeObject()J

    .line 68
    .line 69
    .line 70
    move-result-wide v15

    .line 71
    iget-object v1, v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->scene:Lcom/google/android/filament/Scene;

    .line 72
    .line 73
    invoke-virtual {v1}, Lcom/google/android/filament/Scene;->getNativeObject()J

    .line 74
    .line 75
    .line 76
    move-result-wide v17

    .line 77
    iget-object v1, v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->renderer:Lcom/google/android/filament/Renderer;

    .line 78
    .line 79
    invoke-virtual {v1}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 80
    .line 81
    .line 82
    move-result-wide v19

    .line 83
    move-object/from16 v1, p0

    .line 84
    .line 85
    iget-wide v3, v1, Lcom/google/android/filament/utils/AutomationEngine;->mNativeObject:J

    .line 86
    .line 87
    invoke-virtual/range {p1 .. p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 88
    .line 89
    .line 90
    move-result-wide v5

    .line 91
    iget v13, v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->sunlight:I

    .line 92
    .line 93
    iget-object v14, v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->assetLights:[I

    .line 94
    .line 95
    move-object/from16 v7, p2

    .line 96
    .line 97
    invoke-static/range {v3 .. v20}, Lcom/google/android/filament/utils/AutomationEngine;->nApplySettings(JJLjava/lang/String;J[JJI[IJJJ)V

    .line 98
    .line 99
    .line 100
    return-void

    .line 101
    :cond_3
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 102
    .line 103
    const-string v1, "Must provide a LightManager and Scene"

    .line 104
    .line 105
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 106
    .line 107
    .line 108
    throw v0

    .line 109
    :cond_4
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 110
    .line 111
    const-string v1, "Must provide a View and Renderer"

    .line 112
    .line 113
    invoke-direct {v0, v1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 114
    .line 115
    .line 116
    throw v0
.end method

.method public finalize()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/AutomationEngine;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/AutomationEngine;->nDestroy(J)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->finalize()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public getColorGrading(Lcom/google/android/filament/Engine;)Lcom/google/android/filament/ColorGrading;
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/AutomationEngine;->mNativeObject:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/utils/AutomationEngine;->nGetColorGrading(JJ)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    iget-object p1, p0, Lcom/google/android/filament/utils/AutomationEngine;->mColorGrading:Lcom/google/android/filament/ColorGrading;

    .line 12
    .line 13
    if-eqz p1, :cond_0

    .line 14
    .line 15
    invoke-virtual {p1}, Lcom/google/android/filament/ColorGrading;->getNativeObject()J

    .line 16
    .line 17
    .line 18
    move-result-wide v2

    .line 19
    cmp-long p1, v2, v0

    .line 20
    .line 21
    if-eqz p1, :cond_2

    .line 22
    .line 23
    :cond_0
    const-wide/16 v2, 0x0

    .line 24
    .line 25
    cmp-long p1, v0, v2

    .line 26
    .line 27
    if-nez p1, :cond_1

    .line 28
    .line 29
    const/4 p1, 0x0

    .line 30
    goto :goto_0

    .line 31
    :cond_1
    new-instance p1, Lcom/google/android/filament/ColorGrading;

    .line 32
    .line 33
    invoke-direct {p1, v0, v1}, Lcom/google/android/filament/ColorGrading;-><init>(J)V

    .line 34
    .line 35
    .line 36
    :goto_0
    iput-object p1, p0, Lcom/google/android/filament/utils/AutomationEngine;->mColorGrading:Lcom/google/android/filament/ColorGrading;

    .line 37
    .line 38
    :cond_2
    iget-object p0, p0, Lcom/google/android/filament/utils/AutomationEngine;->mColorGrading:Lcom/google/android/filament/ColorGrading;

    .line 39
    .line 40
    return-object p0
.end method

.method public getViewerOptions()Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;
    .locals 3

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/filament/utils/AutomationEngine$ViewerOptions;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-wide v1, p0, Lcom/google/android/filament/utils/AutomationEngine;->mNativeObject:J

    .line 7
    .line 8
    invoke-static {v1, v2, v0}, Lcom/google/android/filament/utils/AutomationEngine;->nGetViewerOptions(JLjava/lang/Object;)V

    .line 9
    .line 10
    .line 11
    return-object v0
.end method

.method public setOptions(Lcom/google/android/filament/utils/AutomationEngine$Options;)V
    .locals 3

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/AutomationEngine;->mNativeObject:J

    .line 2
    .line 3
    iget p0, p1, Lcom/google/android/filament/utils/AutomationEngine$Options;->sleepDuration:F

    .line 4
    .line 5
    iget v2, p1, Lcom/google/android/filament/utils/AutomationEngine$Options;->minFrameCount:I

    .line 6
    .line 7
    iget-boolean p1, p1, Lcom/google/android/filament/utils/AutomationEngine$Options;->verbose:Z

    .line 8
    .line 9
    invoke-static {v0, v1, p0, v2, p1}, Lcom/google/android/filament/utils/AutomationEngine;->nSetOptions(JFIZ)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public shouldClose()Z
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/AutomationEngine;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/AutomationEngine;->nShouldClose(J)Z

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public signalBatchMode()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/AutomationEngine;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/AutomationEngine;->nSignalBatchMode(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public startBatchMode()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/AutomationEngine;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/AutomationEngine;->nStartBatchMode(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public startRunning()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/AutomationEngine;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/AutomationEngine;->nStartRunning(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public stopRunning()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/AutomationEngine;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/AutomationEngine;->nStopRunning(J)V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public tick(Lcom/google/android/filament/Engine;Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;F)V
    .locals 12

    .line 1
    iget-object v0, p2, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->view:Lcom/google/android/filament/View;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    iget-object v0, p2, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->renderer:Lcom/google/android/filament/Renderer;

    .line 6
    .line 7
    if-eqz v0, :cond_2

    .line 8
    .line 9
    iget-object v0, p2, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->materials:[Lcom/google/android/filament/MaterialInstance;

    .line 10
    .line 11
    if-eqz v0, :cond_1

    .line 12
    .line 13
    array-length v0, v0

    .line 14
    new-array v1, v0, [J

    .line 15
    .line 16
    const/4 v2, 0x0

    .line 17
    :goto_0
    if-ge v2, v0, :cond_0

    .line 18
    .line 19
    iget-object v3, p2, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->materials:[Lcom/google/android/filament/MaterialInstance;

    .line 20
    .line 21
    aget-object v3, v3, v2

    .line 22
    .line 23
    invoke-virtual {v3}, Lcom/google/android/filament/MaterialInstance;->getNativeObject()J

    .line 24
    .line 25
    .line 26
    move-result-wide v3

    .line 27
    aput-wide v3, v1, v2

    .line 28
    .line 29
    add-int/lit8 v2, v2, 0x1

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_0
    :goto_1
    move-object v8, v1

    .line 33
    goto :goto_2

    .line 34
    :cond_1
    const/4 v1, 0x0

    .line 35
    goto :goto_1

    .line 36
    :goto_2
    iget-object v0, p2, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->view:Lcom/google/android/filament/View;

    .line 37
    .line 38
    invoke-virtual {v0}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 39
    .line 40
    .line 41
    move-result-wide v6

    .line 42
    iget-object p2, p2, Lcom/google/android/filament/utils/AutomationEngine$ViewerContent;->renderer:Lcom/google/android/filament/Renderer;

    .line 43
    .line 44
    invoke-virtual {p2}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 45
    .line 46
    .line 47
    move-result-wide v9

    .line 48
    iget-wide v2, p0, Lcom/google/android/filament/utils/AutomationEngine;->mNativeObject:J

    .line 49
    .line 50
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 51
    .line 52
    .line 53
    move-result-wide v4

    .line 54
    move v11, p3

    .line 55
    invoke-static/range {v2 .. v11}, Lcom/google/android/filament/utils/AutomationEngine;->nTick(JJJ[JJF)V

    .line 56
    .line 57
    .line 58
    return-void

    .line 59
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 60
    .line 61
    const-string p1, "Must provide a View and Renderer"

    .line 62
    .line 63
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 64
    .line 65
    .line 66
    throw p0
.end method
