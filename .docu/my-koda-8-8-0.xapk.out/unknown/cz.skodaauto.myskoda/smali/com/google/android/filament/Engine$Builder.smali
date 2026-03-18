.class public Lcom/google/android/filament/Engine$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/Engine;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Builder"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Engine$Builder$BuilderFinalizer;
    }
.end annotation


# instance fields
.field private mConfig:Lcom/google/android/filament/Engine$Config;

.field private final mFinalizer:Lcom/google/android/filament/Engine$Builder$BuilderFinalizer;

.field private final mNativeBuilder:J


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lcom/google/android/filament/Engine;->b()J

    .line 5
    .line 6
    .line 7
    move-result-wide v0

    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/Engine$Builder;->mNativeBuilder:J

    .line 9
    .line 10
    new-instance v2, Lcom/google/android/filament/Engine$Builder$BuilderFinalizer;

    .line 11
    .line 12
    invoke-direct {v2, v0, v1}, Lcom/google/android/filament/Engine$Builder$BuilderFinalizer;-><init>(J)V

    .line 13
    .line 14
    .line 15
    iput-object v2, p0, Lcom/google/android/filament/Engine$Builder;->mFinalizer:Lcom/google/android/filament/Engine$Builder$BuilderFinalizer;

    .line 16
    .line 17
    return-void
.end method


# virtual methods
.method public backend(Lcom/google/android/filament/Engine$Backend;)Lcom/google/android/filament/Engine$Builder;
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Engine$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    int-to-long v2, p1

    .line 8
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->d(JJ)V

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public build()Lcom/google/android/filament/Engine;
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Engine$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/Engine;->a(J)J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    const-wide/16 v2, 0x0

    .line 8
    .line 9
    cmp-long v2, v0, v2

    .line 10
    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    new-instance v2, Lcom/google/android/filament/Engine;

    .line 14
    .line 15
    iget-object p0, p0, Lcom/google/android/filament/Engine$Builder;->mConfig:Lcom/google/android/filament/Engine$Config;

    .line 16
    .line 17
    const/4 v3, 0x0

    .line 18
    invoke-direct {v2, v0, v1, p0, v3}, Lcom/google/android/filament/Engine;-><init>(JLcom/google/android/filament/Engine$Config;I)V

    .line 19
    .line 20
    .line 21
    return-object v2

    .line 22
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 23
    .line 24
    const-string v0, "Couldn\'t create Engine"

    .line 25
    .line 26
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 27
    .line 28
    .line 29
    throw p0
.end method

.method public config(Lcom/google/android/filament/Engine$Config;)Lcom/google/android/filament/Engine$Builder;
    .locals 34

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p1

    .line 4
    .line 5
    iput-object v1, v0, Lcom/google/android/filament/Engine$Builder;->mConfig:Lcom/google/android/filament/Engine$Config;

    .line 6
    .line 7
    iget-wide v2, v0, Lcom/google/android/filament/Engine$Builder;->mNativeBuilder:J

    .line 8
    .line 9
    move-wide v5, v2

    .line 10
    iget-wide v3, v1, Lcom/google/android/filament/Engine$Config;->commandBufferSizeMB:J

    .line 11
    .line 12
    move-wide v7, v5

    .line 13
    iget-wide v5, v1, Lcom/google/android/filament/Engine$Config;->perRenderPassArenaSizeMB:J

    .line 14
    .line 15
    move-wide v9, v7

    .line 16
    iget-wide v7, v1, Lcom/google/android/filament/Engine$Config;->driverHandleArenaSizeMB:J

    .line 17
    .line 18
    move-wide v11, v9

    .line 19
    iget-wide v9, v1, Lcom/google/android/filament/Engine$Config;->minCommandBufferSizeMB:J

    .line 20
    .line 21
    move-wide v13, v11

    .line 22
    iget-wide v11, v1, Lcom/google/android/filament/Engine$Config;->perFrameCommandsSizeMB:J

    .line 23
    .line 24
    move-wide v15, v13

    .line 25
    iget-wide v13, v1, Lcom/google/android/filament/Engine$Config;->jobSystemThreadCount:J

    .line 26
    .line 27
    move-wide/from16 v16, v15

    .line 28
    .line 29
    iget-boolean v15, v1, Lcom/google/android/filament/Engine$Config;->disableParallelShaderCompile:Z

    .line 30
    .line 31
    iget-object v2, v1, Lcom/google/android/filament/Engine$Config;->stereoscopicType:Lcom/google/android/filament/Engine$StereoscopicType;

    .line 32
    .line 33
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    move-wide/from16 v18, v3

    .line 38
    .line 39
    move v4, v2

    .line 40
    iget-wide v2, v1, Lcom/google/android/filament/Engine$Config;->stereoscopicEyeCount:J

    .line 41
    .line 42
    move-wide/from16 v20, v2

    .line 43
    .line 44
    iget-wide v2, v1, Lcom/google/android/filament/Engine$Config;->resourceAllocatorCacheSizeMB:J

    .line 45
    .line 46
    move-wide/from16 v22, v2

    .line 47
    .line 48
    iget-wide v2, v1, Lcom/google/android/filament/Engine$Config;->resourceAllocatorCacheMaxAge:J

    .line 49
    .line 50
    iget-boolean v0, v1, Lcom/google/android/filament/Engine$Config;->disableHandleUseAfterFreeCheck:Z

    .line 51
    .line 52
    move/from16 v24, v0

    .line 53
    .line 54
    iget-object v0, v1, Lcom/google/android/filament/Engine$Config;->preferredShaderLanguage:Lcom/google/android/filament/Engine$Config$ShaderLanguage;

    .line 55
    .line 56
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 57
    .line 58
    .line 59
    move-result v0

    .line 60
    move/from16 v25, v0

    .line 61
    .line 62
    iget-boolean v0, v1, Lcom/google/android/filament/Engine$Config;->forceGLES2Context:Z

    .line 63
    .line 64
    iget-boolean v1, v1, Lcom/google/android/filament/Engine$Config;->assertNativeWindowIsValid:Z

    .line 65
    .line 66
    move/from16 v26, v1

    .line 67
    .line 68
    move/from16 v27, v25

    .line 69
    .line 70
    move/from16 v25, v0

    .line 71
    .line 72
    move-wide/from16 v28, v16

    .line 73
    .line 74
    move/from16 v16, v4

    .line 75
    .line 76
    move-wide/from16 v30, v22

    .line 77
    .line 78
    move/from16 v23, v24

    .line 79
    .line 80
    move/from16 v24, v27

    .line 81
    .line 82
    move-wide/from16 v32, v20

    .line 83
    .line 84
    move-wide/from16 v21, v2

    .line 85
    .line 86
    move-wide/from16 v1, v28

    .line 87
    .line 88
    move-wide/from16 v3, v18

    .line 89
    .line 90
    move-wide/from16 v17, v32

    .line 91
    .line 92
    move-wide/from16 v19, v30

    .line 93
    .line 94
    invoke-static/range {v1 .. v26}, Lcom/google/android/filament/Engine;->e(JJJJJJJZIJJJZIZZ)V

    .line 95
    .line 96
    .line 97
    return-object p0
.end method

.method public featureLevel(Lcom/google/android/filament/Engine$FeatureLevel;)Lcom/google/android/filament/Engine$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Engine$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {p1, v0, v1}, Lcom/google/android/filament/Engine;->f(IJ)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public paused(Z)Lcom/google/android/filament/Engine$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Engine$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Engine;->g(JZ)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public sharedContext(Ljava/lang/Object;)Lcom/google/android/filament/Engine$Builder;
    .locals 4

    .line 1
    invoke-static {}, Lcom/google/android/filament/Platform;->get()Lcom/google/android/filament/Platform;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-virtual {v0, p1}, Lcom/google/android/filament/Platform;->validateSharedContext(Ljava/lang/Object;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_0

    .line 10
    .line 11
    iget-wide v0, p0, Lcom/google/android/filament/Engine$Builder;->mNativeBuilder:J

    .line 12
    .line 13
    invoke-static {}, Lcom/google/android/filament/Platform;->get()Lcom/google/android/filament/Platform;

    .line 14
    .line 15
    .line 16
    move-result-object v2

    .line 17
    invoke-virtual {v2, p1}, Lcom/google/android/filament/Platform;->getSharedContextNativeHandle(Ljava/lang/Object;)J

    .line 18
    .line 19
    .line 20
    move-result-wide v2

    .line 21
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/Engine;->h(JJ)V

    .line 22
    .line 23
    .line 24
    return-object p0

    .line 25
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 26
    .line 27
    const-string v0, "Invalid shared context "

    .line 28
    .line 29
    invoke-static {p1, v0}, Lkx/a;->i(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/String;

    .line 30
    .line 31
    .line 32
    move-result-object p1

    .line 33
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 34
    .line 35
    .line 36
    throw p0
.end method
