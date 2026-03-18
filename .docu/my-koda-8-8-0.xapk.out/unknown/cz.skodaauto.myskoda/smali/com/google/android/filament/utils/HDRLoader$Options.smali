.class public final Lcom/google/android/filament/utils/HDRLoader$Options;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcom/google/android/filament/utils/HDRLoader;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Options"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0005\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R\u001a\u0010\u0004\u001a\u00020\u0005X\u0086\u000e\u00a2\u0006\u000e\n\u0000\u001a\u0004\u0008\u0006\u0010\u0007\"\u0004\u0008\u0008\u0010\t\u00a8\u0006\n"
    }
    d2 = {
        "Lcom/google/android/filament/utils/HDRLoader$Options;",
        "",
        "<init>",
        "()V",
        "desiredFormat",
        "Lcom/google/android/filament/Texture$InternalFormat;",
        "getDesiredFormat",
        "()Lcom/google/android/filament/Texture$InternalFormat;",
        "setDesiredFormat",
        "(Lcom/google/android/filament/Texture$InternalFormat;)V",
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


# instance fields
.field private desiredFormat:Lcom/google/android/filament/Texture$InternalFormat;


# direct methods
.method public constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lcom/google/android/filament/Texture$InternalFormat;->RGB16F:Lcom/google/android/filament/Texture$InternalFormat;

    .line 5
    .line 6
    iput-object v0, p0, Lcom/google/android/filament/utils/HDRLoader$Options;->desiredFormat:Lcom/google/android/filament/Texture$InternalFormat;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final getDesiredFormat()Lcom/google/android/filament/Texture$InternalFormat;
    .locals 0

    .line 1
    iget-object p0, p0, Lcom/google/android/filament/utils/HDRLoader$Options;->desiredFormat:Lcom/google/android/filament/Texture$InternalFormat;

    .line 2
    .line 3
    return-object p0
.end method

.method public final setDesiredFormat(Lcom/google/android/filament/Texture$InternalFormat;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Lcom/google/android/filament/utils/HDRLoader$Options;->desiredFormat:Lcom/google/android/filament/Texture$InternalFormat;

    .line 7
    .line 8
    return-void
.end method
