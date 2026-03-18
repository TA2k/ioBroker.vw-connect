.class public Lcom/google/android/filament/Engine$Config;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/Engine;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Config"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Engine$Config$ShaderLanguage;
    }
.end annotation


# static fields
.field private static final FILAMENT_COMMAND_BUFFER_SIZE_IN_MB:J = 0x3L

.field private static final FILAMENT_MIN_COMMAND_BUFFERS_SIZE_IN_MB:J = 0x1L

.field private static final FILAMENT_PER_FRAME_COMMANDS_SIZE_IN_MB:J = 0x2L

.field private static final FILAMENT_PER_RENDER_PASS_ARENA_SIZE_IN_MB:J = 0x3L


# instance fields
.field public assertNativeWindowIsValid:Z

.field public commandBufferSizeMB:J

.field public disableHandleUseAfterFreeCheck:Z

.field public disableParallelShaderCompile:Z

.field public driverHandleArenaSizeMB:J

.field public forceGLES2Context:Z

.field public jobSystemThreadCount:J

.field public minCommandBufferSizeMB:J

.field public perFrameCommandsSizeMB:J

.field public perRenderPassArenaSizeMB:J

.field public preferredShaderLanguage:Lcom/google/android/filament/Engine$Config$ShaderLanguage;

.field public resourceAllocatorCacheMaxAge:J

.field public resourceAllocatorCacheSizeMB:J

.field public stereoscopicEyeCount:J

.field public stereoscopicType:Lcom/google/android/filament/Engine$StereoscopicType;

.field public textureUseAfterFreePoolSize:J


# direct methods
.method public constructor <init>()V
    .locals 6

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-wide/16 v0, 0x3

    .line 5
    .line 6
    iput-wide v0, p0, Lcom/google/android/filament/Engine$Config;->commandBufferSizeMB:J

    .line 7
    .line 8
    iput-wide v0, p0, Lcom/google/android/filament/Engine$Config;->perRenderPassArenaSizeMB:J

    .line 9
    .line 10
    const-wide/16 v0, 0x0

    .line 11
    .line 12
    iput-wide v0, p0, Lcom/google/android/filament/Engine$Config;->driverHandleArenaSizeMB:J

    .line 13
    .line 14
    const-wide/16 v2, 0x1

    .line 15
    .line 16
    iput-wide v2, p0, Lcom/google/android/filament/Engine$Config;->minCommandBufferSizeMB:J

    .line 17
    .line 18
    const-wide/16 v4, 0x2

    .line 19
    .line 20
    iput-wide v4, p0, Lcom/google/android/filament/Engine$Config;->perFrameCommandsSizeMB:J

    .line 21
    .line 22
    iput-wide v0, p0, Lcom/google/android/filament/Engine$Config;->jobSystemThreadCount:J

    .line 23
    .line 24
    iput-wide v0, p0, Lcom/google/android/filament/Engine$Config;->textureUseAfterFreePoolSize:J

    .line 25
    .line 26
    const/4 v0, 0x0

    .line 27
    iput-boolean v0, p0, Lcom/google/android/filament/Engine$Config;->disableParallelShaderCompile:Z

    .line 28
    .line 29
    sget-object v1, Lcom/google/android/filament/Engine$StereoscopicType;->NONE:Lcom/google/android/filament/Engine$StereoscopicType;

    .line 30
    .line 31
    iput-object v1, p0, Lcom/google/android/filament/Engine$Config;->stereoscopicType:Lcom/google/android/filament/Engine$StereoscopicType;

    .line 32
    .line 33
    iput-wide v4, p0, Lcom/google/android/filament/Engine$Config;->stereoscopicEyeCount:J

    .line 34
    .line 35
    const-wide/16 v4, 0x40

    .line 36
    .line 37
    iput-wide v4, p0, Lcom/google/android/filament/Engine$Config;->resourceAllocatorCacheSizeMB:J

    .line 38
    .line 39
    iput-wide v2, p0, Lcom/google/android/filament/Engine$Config;->resourceAllocatorCacheMaxAge:J

    .line 40
    .line 41
    iput-boolean v0, p0, Lcom/google/android/filament/Engine$Config;->disableHandleUseAfterFreeCheck:Z

    .line 42
    .line 43
    sget-object v1, Lcom/google/android/filament/Engine$Config$ShaderLanguage;->DEFAULT:Lcom/google/android/filament/Engine$Config$ShaderLanguage;

    .line 44
    .line 45
    iput-object v1, p0, Lcom/google/android/filament/Engine$Config;->preferredShaderLanguage:Lcom/google/android/filament/Engine$Config$ShaderLanguage;

    .line 46
    .line 47
    iput-boolean v0, p0, Lcom/google/android/filament/Engine$Config;->forceGLES2Context:Z

    .line 48
    .line 49
    iput-boolean v0, p0, Lcom/google/android/filament/Engine$Config;->assertNativeWindowIsValid:Z

    .line 50
    .line 51
    return-void
.end method
