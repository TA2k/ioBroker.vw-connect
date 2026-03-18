.class public Lcom/google/android/filament/Texture;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/Texture$InternalFormat;,
        Lcom/google/android/filament/Texture$Sampler;,
        Lcom/google/android/filament/Texture$PixelBufferDescriptor;,
        Lcom/google/android/filament/Texture$Type;,
        Lcom/google/android/filament/Texture$CompressedFormat;,
        Lcom/google/android/filament/Texture$Format;,
        Lcom/google/android/filament/Texture$PrefilterOptions;,
        Lcom/google/android/filament/Texture$Usage;,
        Lcom/google/android/filament/Texture$Builder;,
        Lcom/google/android/filament/Texture$Swizzle;,
        Lcom/google/android/filament/Texture$CubemapFace;
    }
.end annotation


# static fields
.field public static final BASE_LEVEL:I

.field private static final sInternalFormatValues:[Lcom/google/android/filament/Texture$InternalFormat;

.field private static final sSamplerValues:[Lcom/google/android/filament/Texture$Sampler;


# instance fields
.field private mNativeObject:J


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lcom/google/android/filament/Texture$Sampler;->values()[Lcom/google/android/filament/Texture$Sampler;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lcom/google/android/filament/Texture;->sSamplerValues:[Lcom/google/android/filament/Texture$Sampler;

    .line 6
    .line 7
    invoke-static {}, Lcom/google/android/filament/Texture$InternalFormat;->values()[Lcom/google/android/filament/Texture$InternalFormat;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    sput-object v0, Lcom/google/android/filament/Texture;->sInternalFormatValues:[Lcom/google/android/filament/Texture$InternalFormat;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lcom/google/android/filament/Texture;->mNativeObject:J

    .line 5
    .line 6
    return-void
.end method

.method public static bridge synthetic a(JJ)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/Texture;->nBuilderBuild(JJ)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic b(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/Texture;->nBuilderDepth(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic c(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/Texture;->nBuilderFormat(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic d(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/Texture;->nBuilderHeight(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e(JJ)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/Texture;->nBuilderImportTexture(JJ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic f(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/Texture;->nBuilderLevels(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic g(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/Texture;->nBuilderSampler(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic h(JIIII)V
    .locals 0

    .line 1
    invoke-static/range {p0 .. p5}, Lcom/google/android/filament/Texture;->nBuilderSwizzle(JIIII)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic i(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/Texture;->nBuilderUsage(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static isTextureFormatSupported(Lcom/google/android/filament/Engine;Lcom/google/android/filament/Texture$InternalFormat;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/Texture;->nIsTextureFormatSupported(JI)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public static isTextureSwizzleSupported(Lcom/google/android/filament/Engine;)Z
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Texture;->nIsTextureSwizzleSupported(J)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public static bridge synthetic j(IJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0}, Lcom/google/android/filament/Texture;->nBuilderWidth(JI)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic k()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/Texture;->nCreateBuilder()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic l(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/Texture;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderBuild(JJ)J
.end method

.method private static native nBuilderDepth(JI)V
.end method

.method private static native nBuilderFormat(JI)V
.end method

.method private static native nBuilderHeight(JI)V
.end method

.method private static native nBuilderImportTexture(JJ)V
.end method

.method private static native nBuilderLevels(JI)V
.end method

.method private static native nBuilderSampler(JI)V
.end method

.method private static native nBuilderSwizzle(JIIII)V
.end method

.method private static native nBuilderUsage(JI)V
.end method

.method private static native nBuilderWidth(JI)V
.end method

.method private static native nCreateBuilder()J
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nGenerateMipmaps(JJ)V
.end method

.method private static native nGeneratePrefilterMipmap(JJIILjava/nio/Buffer;IIIIIII[ILjava/lang/Object;Ljava/lang/Runnable;IZ)I
.end method

.method private static native nGetDepth(JI)I
.end method

.method private static native nGetHeight(JI)I
.end method

.method private static native nGetInternalFormat(J)I
.end method

.method private static native nGetLevels(J)I
.end method

.method private static native nGetTarget(J)I
.end method

.method private static native nGetWidth(JI)I
.end method

.method private static native nIsStreamValidForTexture(JJ)Z
.end method

.method private static native nIsTextureFormatSupported(JI)Z
.end method

.method private static native nIsTextureSwizzleSupported(J)Z
.end method

.method private static native nSetExternalImage(JJJ)V
.end method

.method private static native nSetExternalStream(JJJ)V
.end method

.method private static native nSetImage3D(JJIIIIIIILjava/nio/Buffer;IIIIIIILjava/lang/Object;Ljava/lang/Runnable;)I
.end method

.method private static native nSetImage3DCompressed(JJIIIIIIILjava/nio/Buffer;IIIIIIILjava/lang/Object;Ljava/lang/Runnable;)I
.end method

.method private static native nSetImageCubemap(JJILjava/nio/Buffer;IIIIIII[ILjava/lang/Object;Ljava/lang/Runnable;)I
.end method

.method private static native nSetImageCubemapCompressed(JJILjava/nio/Buffer;IIIIIII[ILjava/lang/Object;Ljava/lang/Runnable;)I
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/Texture;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public generateMipmaps(Lcom/google/android/filament/Engine;)V
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide p0

    .line 9
    invoke-static {v0, v1, p0, p1}, Lcom/google/android/filament/Texture;->nGenerateMipmaps(JJ)V

    .line 10
    .line 11
    .line 12
    return-void
.end method

.method public generatePrefilterMipmap(Lcom/google/android/filament/Engine;Lcom/google/android/filament/Texture$PixelBufferDescriptor;[ILcom/google/android/filament/Texture$PrefilterOptions;)V
    .locals 23

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    move-object/from16 v1, p2

    .line 4
    .line 5
    move-object/from16 v2, p4

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    invoke-virtual {v0, v3}, Lcom/google/android/filament/Texture;->getWidth(I)I

    .line 9
    .line 10
    .line 11
    move-result v8

    .line 12
    invoke-virtual {v0, v3}, Lcom/google/android/filament/Texture;->getHeight(I)I

    .line 13
    .line 14
    .line 15
    move-result v9

    .line 16
    if-eqz v2, :cond_0

    .line 17
    .line 18
    iget v3, v2, Lcom/google/android/filament/Texture$PrefilterOptions;->sampleCount:I

    .line 19
    .line 20
    iget-boolean v2, v2, Lcom/google/android/filament/Texture$PrefilterOptions;->mirror:Z

    .line 21
    .line 22
    :goto_0
    move/from16 v22, v2

    .line 23
    .line 24
    move/from16 v21, v3

    .line 25
    .line 26
    goto :goto_1

    .line 27
    :cond_0
    const/16 v3, 0x8

    .line 28
    .line 29
    const/4 v2, 0x1

    .line 30
    goto :goto_0

    .line 31
    :goto_1
    invoke-virtual {v0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 32
    .line 33
    .line 34
    move-result-wide v4

    .line 35
    invoke-virtual/range {p1 .. p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 36
    .line 37
    .line 38
    move-result-wide v6

    .line 39
    iget-object v10, v1, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->storage:Ljava/nio/Buffer;

    .line 40
    .line 41
    invoke-virtual {v10}, Ljava/nio/Buffer;->remaining()I

    .line 42
    .line 43
    .line 44
    move-result v11

    .line 45
    iget v12, v1, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->left:I

    .line 46
    .line 47
    iget v13, v1, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->top:I

    .line 48
    .line 49
    iget-object v0, v1, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->type:Lcom/google/android/filament/Texture$Type;

    .line 50
    .line 51
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 52
    .line 53
    .line 54
    move-result v14

    .line 55
    iget v15, v1, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->alignment:I

    .line 56
    .line 57
    iget v0, v1, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->stride:I

    .line 58
    .line 59
    iget-object v2, v1, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->format:Lcom/google/android/filament/Texture$Format;

    .line 60
    .line 61
    invoke-virtual {v2}, Ljava/lang/Enum;->ordinal()I

    .line 62
    .line 63
    .line 64
    move-result v17

    .line 65
    iget-object v2, v1, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->handler:Ljava/lang/Object;

    .line 66
    .line 67
    iget-object v1, v1, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->callback:Ljava/lang/Runnable;

    .line 68
    .line 69
    move-object/from16 v18, p3

    .line 70
    .line 71
    move/from16 v16, v0

    .line 72
    .line 73
    move-object/from16 v20, v1

    .line 74
    .line 75
    move-object/from16 v19, v2

    .line 76
    .line 77
    invoke-static/range {v4 .. v22}, Lcom/google/android/filament/Texture;->nGeneratePrefilterMipmap(JJIILjava/nio/Buffer;IIIIIII[ILjava/lang/Object;Ljava/lang/Runnable;IZ)I

    .line 78
    .line 79
    .line 80
    move-result v0

    .line 81
    if-ltz v0, :cond_1

    .line 82
    .line 83
    return-void

    .line 84
    :cond_1
    new-instance v0, Ljava/nio/BufferOverflowException;

    .line 85
    .line 86
    invoke-direct {v0}, Ljava/nio/BufferOverflowException;-><init>()V

    .line 87
    .line 88
    .line 89
    throw v0
.end method

.method public getDepth(I)I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Texture;->nGetDepth(JI)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getFormat()Lcom/google/android/filament/Texture$InternalFormat;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Texture;->sInternalFormatValues:[Lcom/google/android/filament/Texture$InternalFormat;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Texture;->nGetInternalFormat(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    aget-object p0, v0, p0

    .line 12
    .line 13
    return-object p0
.end method

.method public getHeight(I)I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Texture;->nGetHeight(JI)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getLevels()I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1}, Lcom/google/android/filament/Texture;->nGetLevels(J)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public getNativeObject()J
    .locals 4
    .annotation build Lcom/google/android/filament/proguard/UsedByReflection;
        value = "TextureHelper.java"
    .end annotation

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/Texture;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed Texture"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getTarget()Lcom/google/android/filament/Texture$Sampler;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/Texture;->sSamplerValues:[Lcom/google/android/filament/Texture$Sampler;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-static {v1, v2}, Lcom/google/android/filament/Texture;->nGetTarget(J)I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    aget-object p0, v0, p0

    .line 12
    .line 13
    return-object p0
.end method

.method public getWidth(I)I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-static {v0, v1, p1}, Lcom/google/android/filament/Texture;->nGetWidth(JI)I

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public setExternalImage(Lcom/google/android/filament/Engine;J)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v2

    .line 9
    move-wide v4, p2

    .line 10
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/Texture;->nSetExternalImage(JJJ)V

    .line 11
    .line 12
    .line 13
    return-void
.end method

.method public setExternalStream(Lcom/google/android/filament/Engine;Lcom/google/android/filament/Stream;)V
    .locals 6

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    invoke-virtual {p2}, Lcom/google/android/filament/Stream;->getNativeObject()J

    .line 6
    .line 7
    .line 8
    move-result-wide v4

    .line 9
    invoke-static {v0, v1, v4, v5}, Lcom/google/android/filament/Texture;->nIsStreamValidForTexture(JJ)Z

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    if-eqz p0, :cond_0

    .line 14
    .line 15
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 16
    .line 17
    .line 18
    move-result-wide v2

    .line 19
    invoke-static/range {v0 .. v5}, Lcom/google/android/filament/Texture;->nSetExternalStream(JJJ)V

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 24
    .line 25
    const-string p1, "Invalid texture sampler: When used with a stream, a texture must use a SAMPLER_EXTERNAL"

    .line 26
    .line 27
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 28
    .line 29
    .line 30
    throw p0
.end method

.method public setImage(Lcom/google/android/filament/Engine;IIIIIIILcom/google/android/filament/Texture$PixelBufferDescriptor;)V
    .locals 24

    move-object/from16 v0, p9

    .line 3
    iget-object v1, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->type:Lcom/google/android/filament/Texture$Type;

    sget-object v2, Lcom/google/android/filament/Texture$Type;->COMPRESSED:Lcom/google/android/filament/Texture$Type;

    if-ne v1, v2, :cond_0

    .line 4
    invoke-virtual/range {p0 .. p0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    move-result-wide v3

    invoke-virtual/range {p1 .. p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v5

    iget-object v14, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->storage:Ljava/nio/Buffer;

    .line 5
    invoke-virtual {v14}, Ljava/nio/Buffer;->remaining()I

    move-result v15

    iget v1, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->left:I

    iget v2, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->top:I

    iget-object v7, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->type:Lcom/google/android/filament/Texture$Type;

    .line 6
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    move-result v18

    iget v7, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->alignment:I

    iget v8, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->compressedSizeInBytes:I

    iget-object v9, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->compressedFormat:Lcom/google/android/filament/Texture$CompressedFormat;

    .line 7
    invoke-virtual {v9}, Ljava/lang/Enum;->ordinal()I

    move-result v21

    iget-object v9, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->handler:Ljava/lang/Object;

    iget-object v0, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->callback:Ljava/lang/Runnable;

    move/from16 v10, p5

    move/from16 v11, p6

    move/from16 v12, p7

    move/from16 v13, p8

    move-object/from16 v23, v0

    move/from16 v16, v1

    move/from16 v17, v2

    move/from16 v19, v7

    move/from16 v20, v8

    move-object/from16 v22, v9

    move/from16 v7, p2

    move/from16 v8, p3

    move/from16 v9, p4

    .line 8
    invoke-static/range {v3 .. v23}, Lcom/google/android/filament/Texture;->nSetImage3DCompressed(JJIIIIIIILjava/nio/Buffer;IIIIIIILjava/lang/Object;Ljava/lang/Runnable;)I

    move-result v0

    goto :goto_0

    .line 9
    :cond_0
    invoke-virtual/range {p0 .. p0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    move-result-wide v1

    invoke-virtual/range {p1 .. p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v3

    iget-object v12, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->storage:Ljava/nio/Buffer;

    .line 10
    invoke-virtual {v12}, Ljava/nio/Buffer;->remaining()I

    move-result v13

    iget v14, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->left:I

    iget v15, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->top:I

    iget-object v5, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->type:Lcom/google/android/filament/Texture$Type;

    .line 11
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    move-result v16

    iget v5, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->alignment:I

    iget v6, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->stride:I

    iget-object v7, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->format:Lcom/google/android/filament/Texture$Format;

    .line 12
    invoke-virtual {v7}, Ljava/lang/Enum;->ordinal()I

    move-result v19

    iget-object v7, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->handler:Ljava/lang/Object;

    iget-object v0, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->callback:Ljava/lang/Runnable;

    move/from16 v8, p5

    move/from16 v9, p6

    move/from16 v10, p7

    move/from16 v11, p8

    move-object/from16 v21, v0

    move/from16 v17, v5

    move/from16 v18, v6

    move-object/from16 v20, v7

    move/from16 v5, p2

    move/from16 v6, p3

    move/from16 v7, p4

    .line 13
    invoke-static/range {v1 .. v21}, Lcom/google/android/filament/Texture;->nSetImage3D(JJIIIIIIILjava/nio/Buffer;IIIIIIILjava/lang/Object;Ljava/lang/Runnable;)I

    move-result v0

    :goto_0
    if-ltz v0, :cond_1

    return-void

    .line 14
    :cond_1
    new-instance v0, Ljava/nio/BufferOverflowException;

    invoke-direct {v0}, Ljava/nio/BufferOverflowException;-><init>()V

    throw v0
.end method

.method public setImage(Lcom/google/android/filament/Engine;IIIIILcom/google/android/filament/Texture$PixelBufferDescriptor;)V
    .locals 10

    const/4 v5, 0x0

    const/4 v8, 0x1

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move v3, p3

    move v4, p4

    move v6, p5

    move/from16 v7, p6

    move-object/from16 v9, p7

    .line 2
    invoke-virtual/range {v0 .. v9}, Lcom/google/android/filament/Texture;->setImage(Lcom/google/android/filament/Engine;IIIIIIILcom/google/android/filament/Texture$PixelBufferDescriptor;)V

    return-void
.end method

.method public setImage(Lcom/google/android/filament/Engine;ILcom/google/android/filament/Texture$PixelBufferDescriptor;)V
    .locals 10

    .line 1
    invoke-virtual {p0, p2}, Lcom/google/android/filament/Texture;->getWidth(I)I

    move-result v6

    invoke-virtual {p0, p2}, Lcom/google/android/filament/Texture;->getHeight(I)I

    move-result v7

    const/4 v8, 0x1

    const/4 v3, 0x0

    const/4 v4, 0x0

    const/4 v5, 0x0

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move-object v9, p3

    invoke-virtual/range {v0 .. v9}, Lcom/google/android/filament/Texture;->setImage(Lcom/google/android/filament/Engine;IIIIIIILcom/google/android/filament/Texture$PixelBufferDescriptor;)V

    return-void
.end method

.method public setImage(Lcom/google/android/filament/Engine;ILcom/google/android/filament/Texture$PixelBufferDescriptor;[I)V
    .locals 19
    .annotation runtime Ljava/lang/Deprecated;
    .end annotation

    move-object/from16 v0, p3

    .line 15
    iget-object v1, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->type:Lcom/google/android/filament/Texture$Type;

    sget-object v2, Lcom/google/android/filament/Texture$Type;->COMPRESSED:Lcom/google/android/filament/Texture$Type;

    if-ne v1, v2, :cond_0

    .line 16
    invoke-virtual/range {p0 .. p0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    move-result-wide v3

    invoke-virtual/range {p1 .. p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v5

    iget-object v8, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->storage:Ljava/nio/Buffer;

    .line 17
    invoke-virtual {v8}, Ljava/nio/Buffer;->remaining()I

    move-result v9

    iget v10, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->left:I

    iget v11, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->top:I

    iget-object v1, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->type:Lcom/google/android/filament/Texture$Type;

    .line 18
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v12

    iget v13, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->alignment:I

    iget v14, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->compressedSizeInBytes:I

    iget-object v1, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->compressedFormat:Lcom/google/android/filament/Texture$CompressedFormat;

    .line 19
    invoke-virtual {v1}, Ljava/lang/Enum;->ordinal()I

    move-result v15

    iget-object v1, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->handler:Ljava/lang/Object;

    iget-object v0, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->callback:Ljava/lang/Runnable;

    move/from16 v7, p2

    move-object/from16 v16, p4

    move-object/from16 v18, v0

    move-object/from16 v17, v1

    .line 20
    invoke-static/range {v3 .. v18}, Lcom/google/android/filament/Texture;->nSetImageCubemapCompressed(JJILjava/nio/Buffer;IIIIIII[ILjava/lang/Object;Ljava/lang/Runnable;)I

    move-result v0

    goto :goto_0

    .line 21
    :cond_0
    invoke-virtual/range {p0 .. p0}, Lcom/google/android/filament/Texture;->getNativeObject()J

    move-result-wide v1

    invoke-virtual/range {p1 .. p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v3

    iget-object v6, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->storage:Ljava/nio/Buffer;

    .line 22
    invoke-virtual {v6}, Ljava/nio/Buffer;->remaining()I

    move-result v7

    iget v8, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->left:I

    iget v9, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->top:I

    iget-object v5, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->type:Lcom/google/android/filament/Texture$Type;

    .line 23
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    move-result v10

    iget v11, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->alignment:I

    iget v12, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->stride:I

    iget-object v5, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->format:Lcom/google/android/filament/Texture$Format;

    .line 24
    invoke-virtual {v5}, Ljava/lang/Enum;->ordinal()I

    move-result v13

    iget-object v15, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->handler:Ljava/lang/Object;

    iget-object v0, v0, Lcom/google/android/filament/Texture$PixelBufferDescriptor;->callback:Ljava/lang/Runnable;

    move/from16 v5, p2

    move-object/from16 v14, p4

    move-object/from16 v16, v0

    .line 25
    invoke-static/range {v1 .. v16}, Lcom/google/android/filament/Texture;->nSetImageCubemap(JJILjava/nio/Buffer;IIIIIII[ILjava/lang/Object;Ljava/lang/Runnable;)I

    move-result v0

    :goto_0
    if-ltz v0, :cond_1

    return-void

    .line 26
    :cond_1
    new-instance v0, Ljava/nio/BufferOverflowException;

    invoke-direct {v0}, Ljava/nio/BufferOverflowException;-><init>()V

    throw v0
.end method
