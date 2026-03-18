.class public Lcom/google/android/filament/RenderTarget$Builder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/RenderTarget;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "Builder"
.end annotation

.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/RenderTarget$Builder$BuilderFinalizer;
    }
.end annotation


# instance fields
.field private final mFinalizer:Lcom/google/android/filament/RenderTarget$Builder$BuilderFinalizer;

.field private final mNativeBuilder:J

.field private final mTextures:[Lcom/google/android/filament/Texture;


# direct methods
.method public constructor <init>()V
    .locals 3

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lcom/google/android/filament/RenderTarget;->a()I

    .line 5
    .line 6
    .line 7
    move-result v0

    .line 8
    new-array v0, v0, [Lcom/google/android/filament/Texture;

    .line 9
    .line 10
    iput-object v0, p0, Lcom/google/android/filament/RenderTarget$Builder;->mTextures:[Lcom/google/android/filament/Texture;

    .line 11
    .line 12
    invoke-static {}, Lcom/google/android/filament/RenderTarget;->g()J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    iput-wide v0, p0, Lcom/google/android/filament/RenderTarget$Builder;->mNativeBuilder:J

    .line 17
    .line 18
    new-instance v2, Lcom/google/android/filament/RenderTarget$Builder$BuilderFinalizer;

    .line 19
    .line 20
    invoke-direct {v2, v0, v1}, Lcom/google/android/filament/RenderTarget$Builder$BuilderFinalizer;-><init>(J)V

    .line 21
    .line 22
    .line 23
    iput-object v2, p0, Lcom/google/android/filament/RenderTarget$Builder;->mFinalizer:Lcom/google/android/filament/RenderTarget$Builder$BuilderFinalizer;

    .line 24
    .line 25
    return-void
.end method

.method public static bridge synthetic a(Lcom/google/android/filament/RenderTarget$Builder;)[Lcom/google/android/filament/Texture;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/RenderTarget$Builder;->mTextures:[Lcom/google/android/filament/Texture;

    .line 2
    .line 3
    return-object p0
.end method


# virtual methods
.method public build(Lcom/google/android/filament/Engine;)Lcom/google/android/filament/RenderTarget;
    .locals 4

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderTarget$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 4
    .line 5
    .line 6
    move-result-wide v2

    .line 7
    invoke-static {v0, v1, v2, v3}, Lcom/google/android/filament/RenderTarget;->b(JJ)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    const-wide/16 v2, 0x0

    .line 12
    .line 13
    cmp-long p1, v0, v2

    .line 14
    .line 15
    if-eqz p1, :cond_0

    .line 16
    .line 17
    new-instance p1, Lcom/google/android/filament/RenderTarget;

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    invoke-direct {p1, v0, v1, p0, v2}, Lcom/google/android/filament/RenderTarget;-><init>(JLcom/google/android/filament/RenderTarget$Builder;I)V

    .line 21
    .line 22
    .line 23
    return-object p1

    .line 24
    :cond_0
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 25
    .line 26
    const-string p1, "Couldn\'t create RenderTarget"

    .line 27
    .line 28
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 29
    .line 30
    .line 31
    throw p0
.end method

.method public face(Lcom/google/android/filament/RenderTarget$AttachmentPoint;Lcom/google/android/filament/Texture$CubemapFace;)Lcom/google/android/filament/RenderTarget$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderTarget$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-virtual {p2}, Ljava/lang/Enum;->ordinal()I

    .line 8
    .line 9
    .line 10
    move-result p2

    .line 11
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderTarget;->c(JII)V

    .line 12
    .line 13
    .line 14
    return-object p0
.end method

.method public layer(Lcom/google/android/filament/RenderTarget$AttachmentPoint;I)Lcom/google/android/filament/RenderTarget$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderTarget$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderTarget;->d(JII)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public mipLevel(Lcom/google/android/filament/RenderTarget$AttachmentPoint;I)Lcom/google/android/filament/RenderTarget$Builder;
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/RenderTarget$Builder;->mNativeBuilder:J

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p1

    .line 7
    invoke-static {v0, v1, p1, p2}, Lcom/google/android/filament/RenderTarget;->e(JII)V

    .line 8
    .line 9
    .line 10
    return-object p0
.end method

.method public texture(Lcom/google/android/filament/RenderTarget$AttachmentPoint;Lcom/google/android/filament/Texture;)Lcom/google/android/filament/RenderTarget$Builder;
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/filament/RenderTarget$Builder;->mTextures:[Lcom/google/android/filament/Texture;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result v1

    .line 7
    aput-object p2, v0, v1

    .line 8
    .line 9
    iget-wide v0, p0, Lcom/google/android/filament/RenderTarget$Builder;->mNativeBuilder:J

    .line 10
    .line 11
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 12
    .line 13
    .line 14
    move-result p1

    .line 15
    if-eqz p2, :cond_0

    .line 16
    .line 17
    invoke-virtual {p2}, Lcom/google/android/filament/Texture;->getNativeObject()J

    .line 18
    .line 19
    .line 20
    move-result-wide v2

    .line 21
    goto :goto_0

    .line 22
    :cond_0
    const-wide/16 v2, 0x0

    .line 23
    .line 24
    :goto_0
    invoke-static {p1, v0, v1, v2, v3}, Lcom/google/android/filament/RenderTarget;->f(IJJ)V

    .line 25
    .line 26
    .line 27
    return-object p0
.end method
