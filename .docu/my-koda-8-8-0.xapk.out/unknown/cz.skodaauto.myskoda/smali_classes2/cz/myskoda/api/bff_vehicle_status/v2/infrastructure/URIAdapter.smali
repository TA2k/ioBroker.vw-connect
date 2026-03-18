.class public final Lcz/myskoda/api/bff_vehicle_status/v2/infrastructure/URIAdapter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001a\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0010\u000e\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0003\u0018\u00002\u00020\u0001B\u0007\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0010\u0010\u0004\u001a\u00020\u00052\u0006\u0010\u0006\u001a\u00020\u0007H\u0007J\u0010\u0010\u0008\u001a\u00020\u00072\u0006\u0010\t\u001a\u00020\u0005H\u0007\u00a8\u0006\n"
    }
    d2 = {
        "Lcz/myskoda/api/bff_vehicle_status/v2/infrastructure/URIAdapter;",
        "",
        "<init>",
        "()V",
        "toJson",
        "",
        "uri",
        "Ljava/net/URI;",
        "fromJson",
        "s",
        "bff-api_release"
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
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method


# virtual methods
.method public final fromJson(Ljava/lang/String;)Ljava/net/URI;
    .locals 1
    .annotation runtime Lcom/squareup/moshi/FromJson;
    .end annotation

    .line 1
    const-string p0, "s"

    .line 2
    .line 3
    const-string v0, "create(...)"

    .line 4
    .line 5
    invoke-static {p1, p0, p1, v0}, Lkx/a;->s(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/net/URI;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method

.method public final toJson(Ljava/net/URI;)Ljava/lang/String;
    .locals 1
    .annotation runtime Lcom/squareup/moshi/ToJson;
    .end annotation

    .line 1
    const-string p0, "uri"

    .line 2
    .line 3
    const-string v0, "toString(...)"

    .line 4
    .line 5
    invoke-static {p1, p0, v0}, Lkx/a;->o(Ljava/net/URI;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
