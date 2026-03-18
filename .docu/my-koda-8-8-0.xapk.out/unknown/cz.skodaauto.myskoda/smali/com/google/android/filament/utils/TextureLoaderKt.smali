.class public final Lcom/google/android/filament/utils/TextureLoaderKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lcom/google/android/filament/utils/TextureLoaderKt$WhenMappings;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000<\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\u001a&\u0010\u0002\u001a\u00020\u00032\u0006\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u00072\u0006\u0010\u0008\u001a\u00020\t2\u0006\u0010\n\u001a\u00020\u000b\u001a\u0010\u0010\u000c\u001a\u00020\r2\u0006\u0010\n\u001a\u00020\u000bH\u0002\u001a\u0010\u0010\u000e\u001a\u00020\u000f2\u0006\u0010\u0010\u001a\u00020\u0011H\u0002\u001a\u0010\u0010\n\u001a\u00020\u00122\u0006\u0010\u0010\u001a\u00020\u0011H\u0002\"\u000e\u0010\u0000\u001a\u00020\u0001X\u0086T\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u0013"
    }
    d2 = {
        "SKIP_BITMAP_COPY",
        "",
        "loadTexture",
        "Lcom/google/android/filament/Texture;",
        "engine",
        "Lcom/google/android/filament/Engine;",
        "resources",
        "Landroid/content/res/Resources;",
        "resourceId",
        "",
        "type",
        "Lcom/google/android/filament/utils/TextureType;",
        "internalFormat",
        "Lcom/google/android/filament/Texture$InternalFormat;",
        "format",
        "Lcom/google/android/filament/Texture$Format;",
        "bitmap",
        "Landroid/graphics/Bitmap;",
        "Lcom/google/android/filament/Texture$Type;",
        "filament-utils-android_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x0,
        0x0
    }
    xi = 0x30
.end annotation


# static fields
.field public static final SKIP_BITMAP_COPY:Z = true


# direct methods
.method private static final format(Landroid/graphics/Bitmap;)Lcom/google/android/filament/Texture$Format;
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    sparse-switch v0, :sswitch_data_0

    .line 14
    .line 15
    .line 16
    goto :goto_0

    .line 17
    :sswitch_0
    const-string v0, "RGB_565"

    .line 18
    .line 19
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    sget-object p0, Lcom/google/android/filament/Texture$Format;->RGB:Lcom/google/android/filament/Texture$Format;

    .line 26
    .line 27
    return-object p0

    .line 28
    :sswitch_1
    const-string v0, "RGBA_F16"

    .line 29
    .line 30
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_0

    .line 35
    .line 36
    sget-object p0, Lcom/google/android/filament/Texture$Format;->RGBA:Lcom/google/android/filament/Texture$Format;

    .line 37
    .line 38
    return-object p0

    .line 39
    :sswitch_2
    const-string v0, "ARGB_8888"

    .line 40
    .line 41
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-eqz p0, :cond_0

    .line 46
    .line 47
    sget-object p0, Lcom/google/android/filament/Texture$Format;->RGBA:Lcom/google/android/filament/Texture$Format;

    .line 48
    .line 49
    return-object p0

    .line 50
    :sswitch_3
    const-string v0, "ALPHA_8"

    .line 51
    .line 52
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    if-eqz p0, :cond_0

    .line 57
    .line 58
    sget-object p0, Lcom/google/android/filament/Texture$Format;->ALPHA:Lcom/google/android/filament/Texture$Format;

    .line 59
    .line 60
    return-object p0

    .line 61
    :cond_0
    :goto_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 62
    .line 63
    const-string v0, "Unknown bitmap configuration"

    .line 64
    .line 65
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :sswitch_data_0
    .sparse-switch
        -0xb519289 -> :sswitch_3
        0xd4fdd93 -> :sswitch_2
        0x665adb60 -> :sswitch_1
        0x6eb51b22 -> :sswitch_0
    .end sparse-switch
.end method

.method private static final internalFormat(Lcom/google/android/filament/utils/TextureType;)Lcom/google/android/filament/Texture$InternalFormat;
    .locals 1

    .line 1
    sget-object v0, Lcom/google/android/filament/utils/TextureLoaderKt$WhenMappings;->$EnumSwitchMapping$0:[I

    .line 2
    .line 3
    invoke-virtual {p0}, Ljava/lang/Enum;->ordinal()I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    aget p0, v0, p0

    .line 8
    .line 9
    const/4 v0, 0x1

    .line 10
    if-eq p0, v0, :cond_2

    .line 11
    .line 12
    const/4 v0, 0x2

    .line 13
    if-eq p0, v0, :cond_1

    .line 14
    .line 15
    const/4 v0, 0x3

    .line 16
    if-ne p0, v0, :cond_0

    .line 17
    .line 18
    sget-object p0, Lcom/google/android/filament/Texture$InternalFormat;->RGBA8:Lcom/google/android/filament/Texture$InternalFormat;

    .line 19
    .line 20
    return-object p0

    .line 21
    :cond_0
    new-instance p0, La8/r0;

    .line 22
    .line 23
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 24
    .line 25
    .line 26
    throw p0

    .line 27
    :cond_1
    sget-object p0, Lcom/google/android/filament/Texture$InternalFormat;->RGBA8:Lcom/google/android/filament/Texture$InternalFormat;

    .line 28
    .line 29
    return-object p0

    .line 30
    :cond_2
    sget-object p0, Lcom/google/android/filament/Texture$InternalFormat;->SRGB8_A8:Lcom/google/android/filament/Texture$InternalFormat;

    .line 31
    .line 32
    return-object p0
.end method

.method public static final loadTexture(Lcom/google/android/filament/Engine;Landroid/content/res/Resources;ILcom/google/android/filament/utils/TextureType;)Lcom/google/android/filament/Texture;
    .locals 3

    .line 1
    const-string v0, "engine"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string v0, "resources"

    .line 7
    .line 8
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string v0, "type"

    .line 12
    .line 13
    invoke-static {p3, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance v0, Landroid/graphics/BitmapFactory$Options;

    .line 17
    .line 18
    invoke-direct {v0}, Landroid/graphics/BitmapFactory$Options;-><init>()V

    .line 19
    .line 20
    .line 21
    sget-object v1, Lcom/google/android/filament/utils/TextureType;->COLOR:Lcom/google/android/filament/utils/TextureType;

    .line 22
    .line 23
    const/4 v2, 0x0

    .line 24
    if-ne p3, v1, :cond_0

    .line 25
    .line 26
    const/4 v1, 0x1

    .line 27
    goto :goto_0

    .line 28
    :cond_0
    move v1, v2

    .line 29
    :goto_0
    iput-boolean v1, v0, Landroid/graphics/BitmapFactory$Options;->inPremultiplied:Z

    .line 30
    .line 31
    invoke-static {p1, p2, v0}, Landroid/graphics/BitmapFactory;->decodeResource(Landroid/content/res/Resources;ILandroid/graphics/BitmapFactory$Options;)Landroid/graphics/Bitmap;

    .line 32
    .line 33
    .line 34
    move-result-object p1

    .line 35
    new-instance p2, Lcom/google/android/filament/Texture$Builder;

    .line 36
    .line 37
    invoke-direct {p2}, Lcom/google/android/filament/Texture$Builder;-><init>()V

    .line 38
    .line 39
    .line 40
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getWidth()I

    .line 41
    .line 42
    .line 43
    move-result v0

    .line 44
    invoke-virtual {p2, v0}, Lcom/google/android/filament/Texture$Builder;->width(I)Lcom/google/android/filament/Texture$Builder;

    .line 45
    .line 46
    .line 47
    move-result-object p2

    .line 48
    invoke-virtual {p1}, Landroid/graphics/Bitmap;->getHeight()I

    .line 49
    .line 50
    .line 51
    move-result v0

    .line 52
    invoke-virtual {p2, v0}, Lcom/google/android/filament/Texture$Builder;->height(I)Lcom/google/android/filament/Texture$Builder;

    .line 53
    .line 54
    .line 55
    move-result-object p2

    .line 56
    sget-object v0, Lcom/google/android/filament/Texture$Sampler;->SAMPLER_2D:Lcom/google/android/filament/Texture$Sampler;

    .line 57
    .line 58
    invoke-virtual {p2, v0}, Lcom/google/android/filament/Texture$Builder;->sampler(Lcom/google/android/filament/Texture$Sampler;)Lcom/google/android/filament/Texture$Builder;

    .line 59
    .line 60
    .line 61
    move-result-object p2

    .line 62
    invoke-static {p3}, Lcom/google/android/filament/utils/TextureLoaderKt;->internalFormat(Lcom/google/android/filament/utils/TextureType;)Lcom/google/android/filament/Texture$InternalFormat;

    .line 63
    .line 64
    .line 65
    move-result-object p3

    .line 66
    invoke-virtual {p2, p3}, Lcom/google/android/filament/Texture$Builder;->format(Lcom/google/android/filament/Texture$InternalFormat;)Lcom/google/android/filament/Texture$Builder;

    .line 67
    .line 68
    .line 69
    move-result-object p2

    .line 70
    const/16 p3, 0xff

    .line 71
    .line 72
    invoke-virtual {p2, p3}, Lcom/google/android/filament/Texture$Builder;->levels(I)Lcom/google/android/filament/Texture$Builder;

    .line 73
    .line 74
    .line 75
    move-result-object p2

    .line 76
    invoke-virtual {p2, p0}, Lcom/google/android/filament/Texture$Builder;->build(Lcom/google/android/filament/Engine;)Lcom/google/android/filament/Texture;

    .line 77
    .line 78
    .line 79
    move-result-object p2

    .line 80
    const-string p3, "build(...)"

    .line 81
    .line 82
    invoke-static {p2, p3}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 83
    .line 84
    .line 85
    invoke-static {p0, p2, v2, p1}, Lcom/google/android/filament/android/TextureHelper;->setBitmap(Lcom/google/android/filament/Engine;Lcom/google/android/filament/Texture;ILandroid/graphics/Bitmap;)V

    .line 86
    .line 87
    .line 88
    invoke-virtual {p2, p0}, Lcom/google/android/filament/Texture;->generateMipmaps(Lcom/google/android/filament/Engine;)V

    .line 89
    .line 90
    .line 91
    return-object p2
.end method

.method private static final type(Landroid/graphics/Bitmap;)Lcom/google/android/filament/Texture$Type;
    .locals 1

    .line 1
    invoke-virtual {p0}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-virtual {p0}, Ljava/lang/Enum;->name()Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 10
    .line 11
    .line 12
    move-result v0

    .line 13
    sparse-switch v0, :sswitch_data_0

    .line 14
    .line 15
    .line 16
    goto :goto_0

    .line 17
    :sswitch_0
    const-string v0, "RGB_565"

    .line 18
    .line 19
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    if-eqz p0, :cond_0

    .line 24
    .line 25
    sget-object p0, Lcom/google/android/filament/Texture$Type;->USHORT_565:Lcom/google/android/filament/Texture$Type;

    .line 26
    .line 27
    return-object p0

    .line 28
    :sswitch_1
    const-string v0, "RGBA_F16"

    .line 29
    .line 30
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 31
    .line 32
    .line 33
    move-result p0

    .line 34
    if-eqz p0, :cond_0

    .line 35
    .line 36
    sget-object p0, Lcom/google/android/filament/Texture$Type;->HALF:Lcom/google/android/filament/Texture$Type;

    .line 37
    .line 38
    return-object p0

    .line 39
    :sswitch_2
    const-string v0, "ARGB_8888"

    .line 40
    .line 41
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    if-eqz p0, :cond_0

    .line 46
    .line 47
    sget-object p0, Lcom/google/android/filament/Texture$Type;->UBYTE:Lcom/google/android/filament/Texture$Type;

    .line 48
    .line 49
    return-object p0

    .line 50
    :sswitch_3
    const-string v0, "ALPHA_8"

    .line 51
    .line 52
    invoke-virtual {p0, v0}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 53
    .line 54
    .line 55
    move-result p0

    .line 56
    if-eqz p0, :cond_0

    .line 57
    .line 58
    sget-object p0, Lcom/google/android/filament/Texture$Type;->USHORT:Lcom/google/android/filament/Texture$Type;

    .line 59
    .line 60
    return-object p0

    .line 61
    :cond_0
    :goto_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 62
    .line 63
    const-string v0, "Unsupported bitmap configuration"

    .line 64
    .line 65
    invoke-direct {p0, v0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 66
    .line 67
    .line 68
    throw p0

    .line 69
    :sswitch_data_0
    .sparse-switch
        -0xb519289 -> :sswitch_3
        0xd4fdd93 -> :sswitch_2
        0x665adb60 -> :sswitch_1
        0x6eb51b22 -> :sswitch_0
    .end sparse-switch
.end method
