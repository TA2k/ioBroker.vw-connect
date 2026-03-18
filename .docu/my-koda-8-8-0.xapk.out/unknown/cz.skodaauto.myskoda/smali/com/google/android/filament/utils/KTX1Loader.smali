.class public final Lcom/google/android/filament/utils/KTX1Loader;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/KTX1Loader$Options;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000L\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0014\n\u0000\n\u0002\u0010\t\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0006\u0008\u00c6\u0002\u0018\u00002\u00020\u0001:\u0001\u001dB\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J \u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u0008\u001a\u00020\t2\u0008\u0008\u0002\u0010\n\u001a\u00020\u000bJ \u0010\u000c\u001a\u00020\r2\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u0008\u001a\u00020\t2\u0008\u0008\u0002\u0010\n\u001a\u00020\u000bJ \u0010\u000e\u001a\u00020\u000f2\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u0008\u001a\u00020\t2\u0008\u0008\u0002\u0010\n\u001a\u00020\u000bJ\u0010\u0010\u0010\u001a\u0004\u0018\u00010\u00112\u0006\u0010\u0008\u001a\u00020\tJ)\u0010\u0012\u001a\u00020\u00132\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0008\u001a\u00020\t2\u0006\u0010\u0015\u001a\u00020\u00162\u0006\u0010\u0017\u001a\u00020\u0018H\u0082 J)\u0010\u0019\u001a\u00020\u00132\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0008\u001a\u00020\t2\u0006\u0010\u0015\u001a\u00020\u00162\u0006\u0010\u0017\u001a\u00020\u0018H\u0082 J!\u0010\u001a\u001a\u00020\u00182\u0006\u0010\u0008\u001a\u00020\t2\u0006\u0010\u0015\u001a\u00020\u00162\u0006\u0010\u001b\u001a\u00020\u0011H\u0082 J)\u0010\u001c\u001a\u00020\u00132\u0006\u0010\u0014\u001a\u00020\u00132\u0006\u0010\u0008\u001a\u00020\t2\u0006\u0010\u0015\u001a\u00020\u00162\u0006\u0010\u0017\u001a\u00020\u0018H\u0082 \u00a8\u0006\u001e"
    }
    d2 = {
        "Lcom/google/android/filament/utils/KTX1Loader;",
        "",
        "<init>",
        "()V",
        "createTexture",
        "Lcom/google/android/filament/Texture;",
        "engine",
        "Lcom/google/android/filament/Engine;",
        "buffer",
        "Ljava/nio/Buffer;",
        "options",
        "Lcom/google/android/filament/utils/KTX1Loader$Options;",
        "createIndirectLight",
        "Lcom/google/android/filament/IndirectLight;",
        "createSkybox",
        "Lcom/google/android/filament/Skybox;",
        "getSphericalHarmonics",
        "",
        "nCreateKTXTexture",
        "",
        "nativeEngine",
        "remaining",
        "",
        "srgb",
        "",
        "nCreateIndirectLight",
        "nGetSphericalHarmonics",
        "outSphericalHarmonics",
        "nCreateSkybox",
        "Options",
        "filament-utils-android_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final INSTANCE:Lcom/google/android/filament/utils/KTX1Loader;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/KTX1Loader;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/filament/utils/KTX1Loader;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/filament/utils/KTX1Loader;->INSTANCE:Lcom/google/android/filament/utils/KTX1Loader;

    .line 7
    .line 8
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static synthetic createIndirectLight$default(Lcom/google/android/filament/utils/KTX1Loader;Lcom/google/android/filament/Engine;Ljava/nio/Buffer;Lcom/google/android/filament/utils/KTX1Loader$Options;ILjava/lang/Object;)Lcom/google/android/filament/IndirectLight;
    .locals 0

    .line 1
    and-int/lit8 p4, p4, 0x4

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    new-instance p3, Lcom/google/android/filament/utils/KTX1Loader$Options;

    .line 6
    .line 7
    invoke-direct {p3}, Lcom/google/android/filament/utils/KTX1Loader$Options;-><init>()V

    .line 8
    .line 9
    .line 10
    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/filament/utils/KTX1Loader;->createIndirectLight(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;Lcom/google/android/filament/utils/KTX1Loader$Options;)Lcom/google/android/filament/IndirectLight;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static synthetic createSkybox$default(Lcom/google/android/filament/utils/KTX1Loader;Lcom/google/android/filament/Engine;Ljava/nio/Buffer;Lcom/google/android/filament/utils/KTX1Loader$Options;ILjava/lang/Object;)Lcom/google/android/filament/Skybox;
    .locals 0

    .line 1
    and-int/lit8 p4, p4, 0x4

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    new-instance p3, Lcom/google/android/filament/utils/KTX1Loader$Options;

    .line 6
    .line 7
    invoke-direct {p3}, Lcom/google/android/filament/utils/KTX1Loader$Options;-><init>()V

    .line 8
    .line 9
    .line 10
    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/filament/utils/KTX1Loader;->createSkybox(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;Lcom/google/android/filament/utils/KTX1Loader$Options;)Lcom/google/android/filament/Skybox;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method public static synthetic createTexture$default(Lcom/google/android/filament/utils/KTX1Loader;Lcom/google/android/filament/Engine;Ljava/nio/Buffer;Lcom/google/android/filament/utils/KTX1Loader$Options;ILjava/lang/Object;)Lcom/google/android/filament/Texture;
    .locals 0

    .line 1
    and-int/lit8 p4, p4, 0x4

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    new-instance p3, Lcom/google/android/filament/utils/KTX1Loader$Options;

    .line 6
    .line 7
    invoke-direct {p3}, Lcom/google/android/filament/utils/KTX1Loader$Options;-><init>()V

    .line 8
    .line 9
    .line 10
    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/filament/utils/KTX1Loader;->createTexture(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;Lcom/google/android/filament/utils/KTX1Loader$Options;)Lcom/google/android/filament/Texture;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method private final native nCreateIndirectLight(JLjava/nio/Buffer;IZ)J
.end method

.method private final native nCreateKTXTexture(JLjava/nio/Buffer;IZ)J
.end method

.method private final native nCreateSkybox(JLjava/nio/Buffer;IZ)J
.end method

.method private final native nGetSphericalHarmonics(Ljava/nio/Buffer;I[F)Z
.end method


# virtual methods
.method public final createIndirectLight(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;Lcom/google/android/filament/utils/KTX1Loader$Options;)Lcom/google/android/filament/IndirectLight;
    .locals 7

    .line 1
    const-string v0, "engine"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "buffer"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "options"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 17
    .line 18
    .line 19
    move-result-wide v2

    .line 20
    invoke-virtual {p2}, Ljava/nio/Buffer;->remaining()I

    .line 21
    .line 22
    .line 23
    move-result v5

    .line 24
    invoke-virtual {p3}, Lcom/google/android/filament/utils/KTX1Loader$Options;->getSrgb()Z

    .line 25
    .line 26
    .line 27
    move-result v6

    .line 28
    move-object v1, p0

    .line 29
    move-object v4, p2

    .line 30
    invoke-direct/range {v1 .. v6}, Lcom/google/android/filament/utils/KTX1Loader;->nCreateIndirectLight(JLjava/nio/Buffer;IZ)J

    .line 31
    .line 32
    .line 33
    move-result-wide p0

    .line 34
    new-instance p2, Lcom/google/android/filament/IndirectLight;

    .line 35
    .line 36
    invoke-direct {p2, p0, p1}, Lcom/google/android/filament/IndirectLight;-><init>(J)V

    .line 37
    .line 38
    .line 39
    return-object p2
.end method

.method public final createSkybox(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;Lcom/google/android/filament/utils/KTX1Loader$Options;)Lcom/google/android/filament/Skybox;
    .locals 7

    .line 1
    const-string v0, "engine"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "buffer"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "options"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 17
    .line 18
    .line 19
    move-result-wide v2

    .line 20
    invoke-virtual {p2}, Ljava/nio/Buffer;->remaining()I

    .line 21
    .line 22
    .line 23
    move-result v5

    .line 24
    invoke-virtual {p3}, Lcom/google/android/filament/utils/KTX1Loader$Options;->getSrgb()Z

    .line 25
    .line 26
    .line 27
    move-result v6

    .line 28
    move-object v1, p0

    .line 29
    move-object v4, p2

    .line 30
    invoke-direct/range {v1 .. v6}, Lcom/google/android/filament/utils/KTX1Loader;->nCreateSkybox(JLjava/nio/Buffer;IZ)J

    .line 31
    .line 32
    .line 33
    move-result-wide p0

    .line 34
    new-instance p2, Lcom/google/android/filament/Skybox;

    .line 35
    .line 36
    invoke-direct {p2, p0, p1}, Lcom/google/android/filament/Skybox;-><init>(J)V

    .line 37
    .line 38
    .line 39
    return-object p2
.end method

.method public final createTexture(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;Lcom/google/android/filament/utils/KTX1Loader$Options;)Lcom/google/android/filament/Texture;
    .locals 7

    .line 1
    const-string v0, "engine"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "buffer"

    .line 7
    .line 8
    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "options"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {p1}, Lcom/google/android/filament/Engine;->getNativeObject()J

    .line 17
    .line 18
    .line 19
    move-result-wide v2

    .line 20
    invoke-virtual {p2}, Ljava/nio/Buffer;->remaining()I

    .line 21
    .line 22
    .line 23
    move-result v5

    .line 24
    invoke-virtual {p3}, Lcom/google/android/filament/utils/KTX1Loader$Options;->getSrgb()Z

    .line 25
    .line 26
    .line 27
    move-result v6

    .line 28
    move-object v1, p0

    .line 29
    move-object v4, p2

    .line 30
    invoke-direct/range {v1 .. v6}, Lcom/google/android/filament/utils/KTX1Loader;->nCreateKTXTexture(JLjava/nio/Buffer;IZ)J

    .line 31
    .line 32
    .line 33
    move-result-wide p0

    .line 34
    new-instance p2, Lcom/google/android/filament/Texture;

    .line 35
    .line 36
    invoke-direct {p2, p0, p1}, Lcom/google/android/filament/Texture;-><init>(J)V

    .line 37
    .line 38
    .line 39
    return-object p2
.end method

.method public final getSphericalHarmonics(Ljava/nio/Buffer;)[F
    .locals 2

    .line 1
    const-string v0, "buffer"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const/16 v0, 0x1b

    .line 7
    .line 8
    new-array v0, v0, [F

    .line 9
    .line 10
    invoke-virtual {p1}, Ljava/nio/Buffer;->remaining()I

    .line 11
    .line 12
    .line 13
    move-result v1

    .line 14
    invoke-direct {p0, p1, v1, v0}, Lcom/google/android/filament/utils/KTX1Loader;->nGetSphericalHarmonics(Ljava/nio/Buffer;I[F)Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    return-object v0

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return-object p0
.end method
