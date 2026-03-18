.class public Lcom/google/android/filament/Renderer;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Renderer$DisplayInfo;,
        Lcom/google/android/filament/Renderer$FrameRateOptions;,
        Lcom/google/android/filament/Renderer$ClearOptions;
    }
.end annotation


# static fields
.field public static final MIRROR_FRAME_FLAG_CLEAR:I = 0x4

.field public static final MIRROR_FRAME_FLAG_COMMIT:I = 0x1

.field public static final MIRROR_FRAME_FLAG_SET_PRESENTATION_TIME:I = 0x2


# instance fields
.field private mClearOptions:Lcom/google/android/filament/Renderer$ClearOptions;

.field private mDisplayInfo:Lcom/google/android/filament/Renderer$DisplayInfo;

.field private final mEngine:Lcom/google/android/filament/Engine;

.field private mFrameRateOptions:Lcom/google/android/filament/Renderer$FrameRateOptions;

.field private mNativeObject:J


# direct methods
.method public constructor <init>(Lcom/google/android/filament/Engine;J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcom/google/android/filament/Renderer;->mEngine:Lcom/google/android/filament/Engine;

    .line 5
    .line 6
    iput-wide p2, p0, Lcom/google/android/filament/Renderer;->mNativeObject:J

    .line 7
    .line 8
    return-void
.end method

.method private static native nBeginFrame(JJJ)Z
.end method

.method private static native nCopyFrame(JJIIIIIIIII)V
.end method

.method private static native nEndFrame(J)V
.end method

.method private static native nGetUserTime(J)D
.end method

.method private static native nReadPixels(JJIIIILjava/nio/Buffer;IIIIIIILjava/lang/Object;Ljava/lang/Runnable;)I
.end method

.method private static native nReadPixelsEx(JJJIIIILjava/nio/Buffer;IIIIIIILjava/lang/Object;Ljava/lang/Runnable;)I
.end method

.method private static native nRender(JJ)V
.end method

.method private static native nRenderStandaloneView(JJ)V
.end method

.method private static native nResetUserTime(J)V
.end method

.method private static native nSetClearOptions(JFFFFZZ)V
.end method

.method private static native nSetDisplayInfo(JF)V
.end method

.method private static native nSetFrameRateOptions(JFFFI)V
.end method

.method private static native nSetPresentationTime(JJ)V
.end method

.method private static native nSetVsyncTime(JJ)V
.end method

.method private static native nSkipFrame(JJ)V
.end method


# virtual methods
.method public beginFrame(Lcom/google/android/filament/SwapChain;J)Z
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/SwapChain;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    move-wide v4, p2

    .line 10
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/Renderer;->nBeginFrame(JJJ)Z

    .line 11
    .line 12
    .line 13
    move-result p0

    .line 14
    return p0
.end method

.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/Renderer;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public copyFrame(Lcom/google/android/filament/SwapChain;Lcom/google/android/filament/Viewport;Lcom/google/android/filament/Viewport;I)V
    .locals 15

    .line 1
    move-object/from16 v0, p2

    .line 2
    .line 3
    move-object/from16 v1, p3

    .line 4
    .line 5
    invoke-virtual {p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    invoke-virtual/range {p1 .. p1}, Lcom/google/android/filament/SwapChain;->getNativeObject()J

    .line 10
    .line 11
    .line 12
    move-result-wide v4

    .line 13
    move-wide v13, v4

    .line 14
    move-wide v5, v2

    .line 15
    move-wide v2, v13

    .line 16
    iget v4, v0, Lcom/google/android/filament/Viewport;->left:I

    .line 17
    .line 18
    move-wide v6, v5

    .line 19
    iget v5, v0, Lcom/google/android/filament/Viewport;->bottom:I

    .line 20
    .line 21
    move-wide v7, v6

    .line 22
    iget v6, v0, Lcom/google/android/filament/Viewport;->width:I

    .line 23
    .line 24
    iget p0, v0, Lcom/google/android/filament/Viewport;->height:I

    .line 25
    .line 26
    move-wide v9, v7

    .line 27
    iget v8, v1, Lcom/google/android/filament/Viewport;->left:I

    .line 28
    .line 29
    move-wide v10, v9

    .line 30
    iget v9, v1, Lcom/google/android/filament/Viewport;->bottom:I

    .line 31
    .line 32
    move-wide v11, v10

    .line 33
    iget v10, v1, Lcom/google/android/filament/Viewport;->width:I

    .line 34
    .line 35
    iget v0, v1, Lcom/google/android/filament/Viewport;->height:I

    .line 36
    .line 37
    move-wide v13, v11

    .line 38
    move v11, v0

    .line 39
    move-wide v0, v13

    .line 40
    move v7, p0

    .line 41
    move/from16 v12, p4

    .line 42
    .line 43
    invoke-static/range {v0 .. v12}, Lcom/google/android/filament/Renderer;->nCopyFrame(JJIIIIIIIII)V

    .line 44
    .line 45
    .line 46
    return-void
.end method

.method public endFrame()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Renderer;->nEndFrame(J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public getClearOptions()Lcom/google/android/filament/Renderer$ClearOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/Renderer;->mClearOptions:Lcom/google/android/filament/Renderer$ClearOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/Renderer$ClearOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/Renderer$ClearOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/Renderer;->mClearOptions:Lcom/google/android/filament/Renderer$ClearOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/Renderer;->mClearOptions:Lcom/google/android/filament/Renderer$ClearOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getDisplayInfo()Lcom/google/android/filament/Renderer$DisplayInfo;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/Renderer;->mDisplayInfo:Lcom/google/android/filament/Renderer$DisplayInfo;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/Renderer$DisplayInfo;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/Renderer$DisplayInfo;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/Renderer;->mDisplayInfo:Lcom/google/android/filament/Renderer$DisplayInfo;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/Renderer;->mDisplayInfo:Lcom/google/android/filament/Renderer$DisplayInfo;

    .line 13
    .line 14
    return-object p0
.end method

.method public getEngine()Lcom/google/android/filament/Engine;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/Renderer;->mEngine:Lcom/google/android/filament/Engine;

    .line 2
    .line 3
    return-object p0
.end method

.method public getFrameRateOptions()Lcom/google/android/filament/Renderer$FrameRateOptions;
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/Renderer;->mFrameRateOptions:Lcom/google/android/filament/Renderer$FrameRateOptions;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lcom/google/android/filament/Renderer$FrameRateOptions;

    .line 6
    .line 7
    invoke-direct {v0}, Lcom/google/android/filament/Renderer$FrameRateOptions;-><init>()V

    .line 8
    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/Renderer;->mFrameRateOptions:Lcom/google/android/filament/Renderer$FrameRateOptions;

    .line 11
    .line 12
    :cond_0
    iget-object p0, p0, Lcom/google/android/filament/Renderer;->mFrameRateOptions:Lcom/google/android/filament/Renderer$FrameRateOptions;

    .line 13
    .line 14
    return-object p0
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Renderer;->mNativeObject:J

    .line 2
    .line 3
    const-wide/16 v2, 0x0

    .line 4
    .line 5
    cmp-long p0, v0, v2

    .line 6
    .line 7
    if-eqz p0, :cond_0

    .line 8
    .line 9
    return-wide v0

    .line 10
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 11
    .line 12
    const-string v0, "Calling method on destroyed Renderer"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getUserTime()D
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Renderer;->nGetUserTime(J)D

    .line 6
    .line 7
    .line 8
    move-result-wide v0

    .line 9
    return-wide v0
.end method

.method public mirrorFrame(Lcom/google/android/filament/SwapChain;Lcom/google/android/filament/Viewport;Lcom/google/android/filament/Viewport;I)V
    .locals 0
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    .line 1
    invoke-virtual {p0, p1, p2, p3, p4}, Lcom/google/android/filament/Renderer;->copyFrame(Lcom/google/android/filament/SwapChain;Lcom/google/android/filament/Viewport;Lcom/google/android/filament/Viewport;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public readPixels(IIIILcom/google/android/filament/Texture$PixelBufferDescriptor;)V
    .locals 20

    move-object/from16 v0, p5

    .line 1
    iget-object v1, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->storage:Ljava/nio/Buffer;

    invoke-virtual {v1}, Ljava/nio/Buffer;->isReadOnly()Z

    move-result v1

    if-nez v1, :cond_1

    .line 2
    invoke-virtual/range {p0 .. p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    move-result-wide v2

    move-object/from16 v1, p0

    iget-object v1, v1, Lcom/google/android/filament/Renderer;->mEngine:Lcom/google/android/filament/Engine;

    invoke-virtual {v1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v4

    iget-object v10, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->storage:Ljava/nio/Buffer;

    .line 3
    invoke-virtual {v10}, Ljava/nio/Buffer;->remaining()I

    move-result v11

    iget v12, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->left:I

    iget v13, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->top:I

    iget-object v1, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->type:Lcom/google/android/filament/Texture$Type;

    .line 4
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v14

    iget v15, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->alignment:I

    iget v1, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->stride:I

    iget-object v6, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->format:Lcom/google/android/filament/Texture$Format;

    .line 5
    invoke-virtual {v6}, Ljava/lang/Enum;->ordinal()I

    move-result v17

    iget-object v6, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->handler:Ljava/lang/Object;

    iget-object v0, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->callback:Ljava/lang/Runnable;

    move/from16 v7, p2

    move/from16 v8, p3

    move/from16 v9, p4

    move-object/from16 v19, v0

    move/from16 v16, v1

    move-object/from16 v18, v6

    move/from16 v6, p1

    .line 6
    invoke-static/range {v2 .. v19}, Lcom/google/android/filament/Renderer;->nReadPixels(JJIIIILjava/nio/Buffer;IIIIIIILjava/lang/Object;Ljava/lang/Runnable;)I

    move-result v0

    if-ltz v0, :cond_0

    return-void

    .line 7
    :cond_0
    new-instance v0, Ljava/nio/BufferOverflowException;

    invoke-direct {v0}, Ljava/nio/BufferOverflowException;-><init>()V

    throw v0

    .line 8
    :cond_1
    new-instance v0, Ljava/nio/ReadOnlyBufferException;

    invoke-direct {v0}, Ljava/nio/ReadOnlyBufferException;-><init>()V

    throw v0
.end method

.method public readPixels(Lcom/google/android/filament/RenderTarget;IIIILcom/google/android/filament/Texture$PixelBufferDescriptor;)V
    .locals 22

    move-object/from16 v0, p6

    .line 9
    iget-object v1, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->storage:Ljava/nio/Buffer;

    invoke-virtual {v1}, Ljava/nio/Buffer;->isReadOnly()Z

    move-result v1

    if-nez v1, :cond_1

    .line 10
    invoke-virtual/range {p0 .. p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    move-result-wide v2

    move-object/from16 v1, p0

    iget-object v1, v1, Lcom/google/android/filament/Renderer;->mEngine:Lcom/google/android/filament/Engine;

    invoke-virtual {v1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v4

    .line 11
    invoke-virtual/range {p1 .. p1}, Lcom/google/android/filament/RenderTarget;->getNativeObject()J

    move-result-wide v6

    iget-object v12, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->storage:Ljava/nio/Buffer;

    .line 12
    invoke-virtual {v12}, Ljava/nio/Buffer;->remaining()I

    move-result v13

    iget v14, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->left:I

    iget v15, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->top:I

    iget-object v1, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->type:Lcom/google/android/filament/Texture$Type;

    .line 13
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v16

    iget v1, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->alignment:I

    iget v8, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->stride:I

    iget-object v9, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->format:Lcom/google/android/filament/Texture$Format;

    .line 14
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    move-result v19

    iget-object v9, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->handler:Ljava/lang/Object;

    iget-object v0, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->callback:Ljava/lang/Runnable;

    move/from16 v10, p4

    move/from16 v11, p5

    move-object/from16 v21, v0

    move/from16 v17, v1

    move/from16 v18, v8

    move-object/from16 v20, v9

    move/from16 v8, p2

    move/from16 v9, p3

    .line 15
    invoke-static/range {v2 .. v21}, Lcom/google/android/filament/Renderer;->nReadPixelsEx(JJJIIIILjava/nio/Buffer;IIIIIIILjava/lang/Object;Ljava/lang/Runnable;)I

    move-result v0

    if-ltz v0, :cond_0

    return-void

    .line 16
    :cond_0
    new-instance v0, Ljava/nio/BufferOverflowException;

    invoke-direct {v0}, Ljava/nio/BufferOverflowException;-><init>()V

    throw v0

    .line 17
    :cond_1
    new-instance v0, Ljava/nio/ReadOnlyBufferException;

    invoke-direct {v0}, Ljava/nio/ReadOnlyBufferException;-><init>()V

    throw v0
.end method

.method public render(Lcom/google/android/filament/View;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Renderer;->nRender(JJ)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public renderStandaloneView(Lcom/google/android/filament/View;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/View;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Renderer;->nRenderStandaloneView(JJ)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public resetUserTime()V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Renderer;->nResetUserTime(J)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setClearOptions(Lcom/google/android/filament/Renderer$ClearOptions;)V
    .locals 8

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/Renderer;->mClearOptions:Lcom/google/android/filament/Renderer$ClearOptions;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget-object p0, p1, Lcom/google/android/filament/Renderer$ClearOptions;->clearColor:[F

    .line 8
    .line 9
    const/4 v2, 0x0

    .line 10
    aget v2, p0, v2

    .line 11
    .line 12
    const/4 v3, 0x1

    .line 13
    aget v3, p0, v3

    .line 14
    .line 15
    const/4 v4, 0x2

    .line 16
    aget v4, p0, v4

    .line 17
    .line 18
    const/4 v5, 0x3

    .line 19
    aget v5, p0, v5

    .line 20
    .line 21
    iget-boolean v6, p1, Lcom/google/android/filament/Renderer$ClearOptions;->clear:Z

    .line 22
    .line 23
    iget-boolean v7, p1, Lcom/google/android/filament/Renderer$ClearOptions;->discard:Z

    .line 24
    .line 25
    invoke-static/range {v0 .. v7}, Lcom/google/android/filament/Renderer;->nSetClearOptions(JFFFFZZ)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

.method public setDisplayInfo(Lcom/google/android/filament/Renderer$DisplayInfo;)V
    .locals 2

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/Renderer;->mDisplayInfo:Lcom/google/android/filament/Renderer$DisplayInfo;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget p0, p1, Lcom/google/android/filament/Renderer$DisplayInfo;->refreshRate:F

    .line 8
    .line 9
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/Renderer;->nSetDisplayInfo(JF)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public setFrameRateOptions(Lcom/google/android/filament/Renderer$FrameRateOptions;)V
    .locals 6

    .line 1
    iput-object p1, p0, Lcom/google/android/filament/Renderer;->mFrameRateOptions:Lcom/google/android/filament/Renderer$FrameRateOptions;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    iget v2, p1, Lcom/google/android/filament/Renderer$FrameRateOptions;->interval:F

    .line 8
    .line 9
    iget v3, p1, Lcom/google/android/filament/Renderer$FrameRateOptions;->headRoomRatio:F

    .line 10
    .line 11
    iget v4, p1, Lcom/google/android/filament/Renderer$FrameRateOptions;->scaleRate:F

    .line 12
    .line 13
    iget v5, p1, Lcom/google/android/filament/Renderer$FrameRateOptions;->history:I

    .line 14
    .line 15
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/Renderer;->nSetFrameRateOptions(JFFFI)V

    .line 16
    .line 17
    .line 18
    return-void
.end method

.method public setPresentationTime(J)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/Renderer;->nSetPresentationTime(JJ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public setVsyncTime(J)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/Renderer;->nSetVsyncTime(JJ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method

.method public skipFrame(J)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Renderer;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/Renderer;->nSkipFrame(JJ)V

    .line 6
    .line 7
    .line 8
    return-void
.end method
