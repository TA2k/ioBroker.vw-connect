.class public final Lcom/google/android/filament/android/TextureHelper;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static final BITMAP_CONFIG_ALPHA_8:I = 0x0

.field private static final BITMAP_CONFIG_HARDWARE:I = 0x5

.field private static final BITMAP_CONFIG_RGBA_4444:I = 0x2

.field private static final BITMAP_CONFIG_RGBA_8888:I = 0x3

.field private static final BITMAP_CONFIG_RGBA_F16:I = 0x4

.field private static final BITMAP_CONFIG_RGB_565:I = 0x1


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method private static native nSetBitmap(JJIIIIILandroid/graphics/Bitmap;I)V
.end method

.method private static native nSetBitmapWithCallback(JJIIIIILandroid/graphics/Bitmap;ILjava/lang/Object;Ljava/lang/Runnable;)V
.end method

.method public static setBitmap(Lcom/google/android/filament/Engine;Lcom/google/android/filament/Texture;IIIIILandroid/graphics/Bitmap;)V
    .locals 12

    .line 5
    invoke-virtual/range {p7 .. p7}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    move-result-object v0

    invoke-static {v0}, Lcom/google/android/filament/android/TextureHelper;->toNativeFormat(Landroid/graphics/Bitmap$Config;)I

    move-result v11

    const/4 v0, 0x2

    if-eq v11, v0, :cond_0

    const/4 v0, 0x5

    if-eq v11, v0, :cond_0

    .line 6
    invoke-virtual {p1}, Lcom/google/android/filament/Texture;->getNativeObject()J

    move-result-wide v1

    .line 7
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v3

    move v5, p2

    move v6, p3

    move/from16 v7, p4

    move/from16 v8, p5

    move/from16 v9, p6

    move-object/from16 v10, p7

    .line 8
    invoke-static/range {v1 .. v11}, Lcom/google/android/filament/android/TextureHelper;->nSetBitmap(JJIIIIILandroid/graphics/Bitmap;I)V

    return-void

    .line 9
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Unsupported config: ARGB_4444 or HARDWARE"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static setBitmap(Lcom/google/android/filament/Engine;Lcom/google/android/filament/Texture;IIIIILandroid/graphics/Bitmap;Ljava/lang/Object;Ljava/lang/Runnable;)V
    .locals 14

    .line 10
    invoke-virtual/range {p7 .. p7}, Landroid/graphics/Bitmap;->getConfig()Landroid/graphics/Bitmap$Config;

    move-result-object v0

    invoke-static {v0}, Lcom/google/android/filament/android/TextureHelper;->toNativeFormat(Landroid/graphics/Bitmap$Config;)I

    move-result v11

    const/4 v0, 0x2

    if-eq v11, v0, :cond_0

    const/4 v0, 0x5

    if-eq v11, v0, :cond_0

    .line 11
    invoke-virtual {p1}, Lcom/google/android/filament/Texture;->getNativeObject()J

    move-result-wide v1

    .line 12
    invoke-virtual {p0}, Lcom/google/android/filament/Engine;->getNativeObject()J

    move-result-wide v3

    move/from16 v5, p2

    move/from16 v6, p3

    move/from16 v7, p4

    move/from16 v8, p5

    move/from16 v9, p6

    move-object/from16 v10, p7

    move-object/from16 v12, p8

    move-object/from16 v13, p9

    .line 13
    invoke-static/range {v1 .. v13}, Lcom/google/android/filament/android/TextureHelper;->nSetBitmapWithCallback(JJIIIIILandroid/graphics/Bitmap;ILjava/lang/Object;Ljava/lang/Runnable;)V

    return-void

    .line 14
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    const-string p1, "Unsupported config: ARGB_4444 or HARDWARE"

    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw p0
.end method

.method public static setBitmap(Lcom/google/android/filament/Engine;Lcom/google/android/filament/Texture;ILandroid/graphics/Bitmap;)V
    .locals 8

    .line 1
    invoke-virtual {p1, p2}, Lcom/google/android/filament/Texture;->getWidth(I)I

    move-result v5

    invoke-virtual {p1, p2}, Lcom/google/android/filament/Texture;->getHeight(I)I

    move-result v6

    const/4 v3, 0x0

    const/4 v4, 0x0

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move-object v7, p3

    .line 2
    invoke-static/range {v0 .. v7}, Lcom/google/android/filament/android/TextureHelper;->setBitmap(Lcom/google/android/filament/Engine;Lcom/google/android/filament/Texture;IIIIILandroid/graphics/Bitmap;)V

    return-void
.end method

.method public static setBitmap(Lcom/google/android/filament/Engine;Lcom/google/android/filament/Texture;ILandroid/graphics/Bitmap;Ljava/lang/Object;Ljava/lang/Runnable;)V
    .locals 10

    .line 3
    invoke-virtual {p1, p2}, Lcom/google/android/filament/Texture;->getWidth(I)I

    move-result v5

    invoke-virtual {p1, p2}, Lcom/google/android/filament/Texture;->getHeight(I)I

    move-result v6

    const/4 v3, 0x0

    const/4 v4, 0x0

    move-object v0, p0

    move-object v1, p1

    move v2, p2

    move-object v7, p3

    move-object v8, p4

    move-object v9, p5

    .line 4
    invoke-static/range {v0 .. v9}, Lcom/google/android/filament/android/TextureHelper;->setBitmap(Lcom/google/android/filament/Engine;Lcom/google/android/filament/Texture;IIIIILandroid/graphics/Bitmap;Ljava/lang/Object;Ljava/lang/Runnable;)V

    return-void
.end method

.method private static toNativeFormat(Landroid/graphics/Bitmap$Config;)I
    .locals 3

    .line 1
    sget-object v0, Lcom/google/android/filament/android/TextureHelper$1;->$SwitchMap$android$graphics$Bitmap$Config:[I

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
    if-eq p0, v0, :cond_4

    .line 11
    .line 12
    const/4 v1, 0x2

    .line 13
    if-eq p0, v1, :cond_3

    .line 14
    .line 15
    const/4 v0, 0x3

    .line 16
    if-eq p0, v0, :cond_2

    .line 17
    .line 18
    const/4 v1, 0x5

    .line 19
    if-eq p0, v1, :cond_1

    .line 20
    .line 21
    const/4 v2, 0x6

    .line 22
    if-eq p0, v2, :cond_0

    .line 23
    .line 24
    return v0

    .line 25
    :cond_0
    return v1

    .line 26
    :cond_1
    const/4 p0, 0x4

    .line 27
    return p0

    .line 28
    :cond_2
    return v1

    .line 29
    :cond_3
    return v0

    .line 30
    :cond_4
    const/4 p0, 0x0

    .line 31
    return p0
.end method
