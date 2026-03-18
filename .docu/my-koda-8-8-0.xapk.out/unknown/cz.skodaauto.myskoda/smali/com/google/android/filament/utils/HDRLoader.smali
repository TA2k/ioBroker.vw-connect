.class public final Lcom/google/android/filament/utils/HDRLoader;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/HDRLoader$Options;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u00004\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\t\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\u0003\u0008\u00c6\u0002\u0018\u00002\u00020\u0001:\u0001\u0012B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\"\u0010\u0004\u001a\u0004\u0018\u00010\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u0008\u001a\u00020\t2\u0008\u0008\u0002\u0010\n\u001a\u00020\u000bJ)\u0010\u000c\u001a\u00020\r2\u0006\u0010\u000e\u001a\u00020\r2\u0006\u0010\u0008\u001a\u00020\t2\u0006\u0010\u000f\u001a\u00020\u00102\u0006\u0010\u0011\u001a\u00020\u0010H\u0082 \u00a8\u0006\u0013"
    }
    d2 = {
        "Lcom/google/android/filament/utils/HDRLoader;",
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
        "Lcom/google/android/filament/utils/HDRLoader$Options;",
        "nCreateHDRTexture",
        "",
        "nativeEngine",
        "remaining",
        "",
        "format",
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
.field public static final INSTANCE:Lcom/google/android/filament/utils/HDRLoader;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lcom/google/android/filament/utils/HDRLoader;

    .line 2
    .line 3
    invoke-direct {v0}, Lcom/google/android/filament/utils/HDRLoader;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lcom/google/android/filament/utils/HDRLoader;->INSTANCE:Lcom/google/android/filament/utils/HDRLoader;

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

.method public static synthetic createTexture$default(Lcom/google/android/filament/utils/HDRLoader;Lcom/google/android/filament/Engine;Ljava/nio/Buffer;Lcom/google/android/filament/utils/HDRLoader$Options;ILjava/lang/Object;)Lcom/google/android/filament/Texture;
    .locals 0

    .line 1
    and-int/lit8 p4, p4, 0x4

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    new-instance p3, Lcom/google/android/filament/utils/HDRLoader$Options;

    .line 6
    .line 7
    invoke-direct {p3}, Lcom/google/android/filament/utils/HDRLoader$Options;-><init>()V

    .line 8
    .line 9
    .line 10
    :cond_0
    invoke-virtual {p0, p1, p2, p3}, Lcom/google/android/filament/utils/HDRLoader;->createTexture(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;Lcom/google/android/filament/utils/HDRLoader$Options;)Lcom/google/android/filament/Texture;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method

.method private final native nCreateHDRTexture(JLjava/nio/Buffer;II)J
.end method


# virtual methods
.method public final createTexture(Lcom/google/android/filament/Engine;Ljava/nio/Buffer;Lcom/google/android/filament/utils/HDRLoader$Options;)Lcom/google/android/filament/Texture;
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
    invoke-virtual {p3}, Lcom/google/android/filament/utils/HDRLoader$Options;->getDesiredFormat()Lcom/google/android/filament/Texture$InternalFormat;

    .line 25
    .line 26
    .line 27
    move-result-object p1

    .line 28
    invoke-virtual {p1}, Ljava/lang/Enum;->ordinal()I

    .line 29
    .line 30
    .line 31
    move-result v6

    .line 32
    move-object v1, p0

    .line 33
    move-object v4, p2

    .line 34
    invoke-direct/range {v1 .. v6}, Lcom/google/android/filament/utils/HDRLoader;->nCreateHDRTexture(JLjava/nio/Buffer;II)J

    .line 35
    .line 36
    .line 37
    move-result-wide p0

    .line 38
    const-wide/16 p2, 0x0

    .line 39
    .line 40
    cmp-long p2, p0, p2

    .line 41
    .line 42
    if-nez p2, :cond_0

    .line 43
    .line 44
    const/4 p0, 0x0

    .line 45
    return-object p0

    .line 46
    :cond_0
    new-instance p2, Lcom/google/android/filament/Texture;

    .line 47
    .line 48
    invoke-direct {p2, p0, p1}, Lcom/google/android/filament/Texture;-><init>(J)V

    .line 49
    .line 50
    .line 51
    return-object p2
.end method
