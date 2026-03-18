.class public final Lcz/myskoda/api/vas/infrastructure/CollectionFormats$SPACEParams;
.super Lcz/myskoda/api/vas/infrastructure/CollectionFormats$SSVParams;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lcz/myskoda/api/vas/infrastructure/CollectionFormats;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "SPACEParams"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u000c\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003\u00a8\u0006\u0004"
    }
    d2 = {
        "Lcz/myskoda/api/vas/infrastructure/CollectionFormats$SPACEParams;",
        "Lcz/myskoda/api/vas/infrastructure/CollectionFormats$SSVParams;",
        "<init>",
        "()V",
        "vas-api_release"
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
.method public constructor <init>()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    new-array v0, v0, [Ljava/lang/String;

    .line 3
    .line 4
    invoke-direct {p0, v0}, Lcz/myskoda/api/vas/infrastructure/CollectionFormats$SSVParams;-><init>([Ljava/lang/String;)V

    .line 5
    .line 6
    .line 7
    return-void
.end method
