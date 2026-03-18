.class public final Lcz/myskoda/api/idk/infrastructure/ApiClient$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcz/myskoda/api/idk/infrastructure/ApiClient;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0014\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0002\u0008\u000b\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003R \u0010\u0005\u001a\u00020\u00048\u0004X\u0085D\u00a2\u0006\u0012\n\u0004\u0008\u0005\u0010\u0006\u0012\u0004\u0008\t\u0010\u0003\u001a\u0004\u0008\u0007\u0010\u0008R!\u0010\u000e\u001a\u00020\u00048FX\u0087\u0084\u0002\u00a2\u0006\u0012\n\u0004\u0008\n\u0010\u000b\u0012\u0004\u0008\r\u0010\u0003\u001a\u0004\u0008\u000c\u0010\u0008\u00a8\u0006\u000f"
    }
    d2 = {
        "Lcz/myskoda/api/idk/infrastructure/ApiClient$Companion;",
        "",
        "<init>",
        "()V",
        "",
        "baseUrlKey",
        "Ljava/lang/String;",
        "getBaseUrlKey",
        "()Ljava/lang/String;",
        "getBaseUrlKey$annotations",
        "defaultBasePath$delegate",
        "Llx0/i;",
        "getDefaultBasePath",
        "getDefaultBasePath$annotations",
        "defaultBasePath",
        "idk-api_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lcz/myskoda/api/idk/infrastructure/ApiClient$Companion;-><init>()V

    return-void
.end method

.method public static synthetic getBaseUrlKey$annotations()V
    .locals 0

    .line 1
    return-void
.end method

.method public static synthetic getDefaultBasePath$annotations()V
    .locals 0

    .line 1
    return-void
.end method


# virtual methods
.method public final getBaseUrlKey()Ljava/lang/String;
    .locals 0

    .line 1
    invoke-static {}, Lcz/myskoda/api/idk/infrastructure/ApiClient;->access$getBaseUrlKey$cp()Ljava/lang/String;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    return-object p0
.end method

.method public final getDefaultBasePath()Ljava/lang/String;
    .locals 1

    .line 1
    invoke-static {}, Lcz/myskoda/api/idk/infrastructure/ApiClient;->access$getDefaultBasePath$delegate$cp()Llx0/i;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    invoke-interface {p0}, Llx0/i;->getValue()Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    const-string v0, "getValue(...)"

    .line 10
    .line 11
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->e(Ljava/lang/Object;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    check-cast p0, Ljava/lang/String;

    .line 15
    .line 16
    return-object p0
.end method
