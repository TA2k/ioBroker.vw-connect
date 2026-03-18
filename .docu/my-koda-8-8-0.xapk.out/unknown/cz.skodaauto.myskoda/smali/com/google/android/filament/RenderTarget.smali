.class public Lcom/google/android/filament/RenderTarget;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/RenderTarget$Builder;,
        Lcom/google/android/filament/RenderTarget$AttachmentPoint;
    }
.end annotation


# static fields
.field private static final ATTACHMENT_COUNT:I

.field private static final sCubemapFaceValues:[Lcom/google/android/filament/Texture$CubemapFace;


# instance fields
.field private mNativeObject:J

.field private final mTextures:[Lcom/google/android/filament/Texture;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lcom/google/android/filament/RenderTarget$AttachmentPoint;->values()[Lcom/google/android/filament/RenderTarget$AttachmentPoint;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    array-length v0, v0

    .line 6
    sput v0, Lcom/google/android/filament/RenderTarget;->ATTACHMENT_COUNT:I

    .line 7
    .line 8
    invoke-static {}, Lcom/google/android/filament/Texture$CubemapFace;->values()[Lcom/google/android/filament/Texture$CubemapFace;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    sput-object v0, Lcom/google/android/filament/RenderTarget;->sCubemapFaceValues:[Lcom/google/android/filament/Texture$CubemapFace;

    .line 13
    .line 14
    return-void
.end method

.method private constructor <init>(JLcom/google/android/filament/RenderTarget$Builder;)V
    .locals 2

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    sget v0, Lcom/google/android/filament/RenderTarget;->ATTACHMENT_COUNT:I

    new-array v1, v0, [Lcom/google/android/filament/Texture;

    iput-object v1, p0, Lcom/google/android/filament/RenderTarget;->mTextures:[Lcom/google/android/filament/Texture;

    .line 4
    iput-wide p1, p0, Lcom/google/android/filament/RenderTarget;->mNativeObject:J

    .line 5
    invoke-static {p3}, Lcom/google/android/filament/RenderTarget$Builder;->a(Lcom/google/android/filament/RenderTarget$Builder;)[Lcom/google/android/filament/Texture;

    move-result-object p0

    const/4 p1, 0x0

    invoke-static {p0, p1, v1, p1, v0}, Ljava/lang/System;->arraycopy(Ljava/lang/Object;ILjava/lang/Object;II)V

    return-void
.end method

.method public synthetic constructor <init>(JLcom/google/android/filament/RenderTarget$Builder;I)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2, p3}, Lcom/google/android/filament/RenderTarget;-><init>(JLcom/google/android/filament/RenderTarget$Builder;)V

    return-void
.end method

.method public static bridge synthetic a()I
    .locals 1

    .line 1
    sget v0, Lcom/google/android/filament/RenderTarget;->ATTACHMENT_COUNT:I

    .line 2
    .line 3
    return v0
.end method

.method public static bridge synthetic b(JJ)J
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/RenderTarget;->nBuilderBuild(JJ)J

    .line 2
    .line 3
    .line 4
    move-result-wide p0

    .line 5
    return-wide p0
.end method

.method public static bridge synthetic c(JII)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/RenderTarget;->nBuilderFace(JII)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic d(JII)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/RenderTarget;->nBuilderLayer(JII)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic e(JII)V
    .locals 0

    .line 1
    invoke-static {p0, p1, p2, p3}, Lcom/google/android/filament/RenderTarget;->nBuilderMipLevel(JII)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic f(IJJ)V
    .locals 0

    .line 1
    invoke-static {p1, p2, p0, p3, p4}, Lcom/google/android/filament/RenderTarget;->nBuilderTexture(JIJ)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static bridge synthetic g()J
    .locals 2

    .line 1
    invoke-static {}, Lcom/google/android/filament/RenderTarget;->nCreateBuilder()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    return-wide v0
.end method

.method public static bridge synthetic h(J)V
    .locals 0

    .line 1
    invoke-static {p0, p1}, Lcom/google/android/filament/RenderTarget;->nDestroyBuilder(J)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nBuilderBuild(JJ)J
.end method

.method private static native nBuilderFace(JII)V
.end method

.method private static native nBuilderLayer(JII)V
.end method

.method private static native nBuilderMipLevel(JII)V
.end method

.method private static native nBuilderTexture(JIJ)V
.end method

.method private static native nCreateBuilder()J
.end method

.method private static native nDestroyBuilder(J)V
.end method

.method private static native nGetFace(JI)I
.end method

.method private static native nGetLayer(JI)I
.end method

.method private static native nGetMipLevel(JI)I
.end method


# virtual methods
.method public clearNativeObject()V
    .locals 2

    .line 1
    const-wide/16 v0, 0x0

    .line 2
    .line 3
    iput-wide v0, p0, Lcom/google/android/filament/RenderTarget;->mNativeObject:J

    .line 4
    .line 5
    return-void
.end method

.method public getFace(Lcom/google/android/filament/RenderTarget$AttachmentPoint;)Lcom/google/android/filament/Texture$CubemapFace;
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/RenderTarget;->sCubemapFaceValues:[Lcom/google/android/filament/Texture$CubemapFace;

    .line 2
    .line 3
    invoke-virtual {p0}, Lcom/google/android/filament/RenderTarget;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result p0

    .line 11
    invoke-static {v1, v2, p0}, Lcom/google/android/filament/RenderTarget;->nGetFace(JI)I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    aget-object p0, v0, p0

    .line 16
    .line 17
    return-object p0
.end method

.method public getLayer(Lcom/google/android/filament/RenderTarget$AttachmentPoint;)I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/RenderTarget;->getNativeObject()J

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
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/RenderTarget;->nGetLayer(JI)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public getMipLevel(Lcom/google/android/filament/RenderTarget$AttachmentPoint;)I
    .locals 2

    .line 1
    invoke-virtual {p0}, Lcom/google/android/filament/RenderTarget;->getNativeObject()J

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
    invoke-static {v0, v1, p0}, Lcom/google/android/filament/RenderTarget;->nGetMipLevel(JI)I

    .line 10
    .line 11
    .line 12
    move-result p0

    .line 13
    return p0
.end method

.method public getNativeObject()J
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderTarget;->mNativeObject:J

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
    const-string v0, "Calling method on destroyed RenderTarget"

    .line 13
    .line 14
    invoke-direct {p0, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    throw p0
.end method

.method public getTexture(Lcom/google/android/filament/RenderTarget$AttachmentPoint;)Lcom/google/android/filament/Texture;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/RenderTarget;->mTextures:[Lcom/google/android/filament/Texture;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    aget-object p0, p0, p1

    .line 8
    .line 9
    return-object p0
.end method
