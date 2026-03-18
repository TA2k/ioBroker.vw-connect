.class public final Lcz/myskoda/api/bff_vehicle_status/v2/infrastructure/ResponseExtKt;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0012\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u001a*\u0010\u0000\u001a\u0004\u0018\u0001H\u0001\"\u0006\u0008\u0000\u0010\u0001\u0018\u0001*\u0006\u0012\u0002\u0008\u00030\u00022\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0004H\u0086\u0008\u00a2\u0006\u0002\u0010\u0005\u00a8\u0006\u0006"
    }
    d2 = {
        "getErrorResponse",
        "T",
        "Lretrofit2/Response;",
        "serializerBuilder",
        "Lcom/squareup/moshi/Moshi$Builder;",
        "(Lretrofit2/Response;Lcom/squareup/moshi/Moshi$Builder;)Ljava/lang/Object;",
        "bff-api_release"
    }
    k = 0x2
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# direct methods
.method public static final getErrorResponse(Lretrofit2/Response;Lcom/squareup/moshi/Moshi$Builder;)Ljava/lang/Object;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lretrofit2/Response<",
            "*>;",
            "Lcom/squareup/moshi/Moshi$Builder;",
            ")TT;"
        }
    .end annotation

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    const-string v1, "serializerBuilder"

    .line 4
    .line 5
    invoke-static {p0, v0, p1, v1, p1}, Lkx/a;->z(Lretrofit2/Response;Ljava/lang/String;Lcom/squareup/moshi/Moshi$Builder;Ljava/lang/String;Lcom/squareup/moshi/Moshi$Builder;)V

    .line 6
    .line 7
    .line 8
    const/4 p0, 0x0

    .line 9
    throw p0
.end method

.method public static getErrorResponse$default(Lretrofit2/Response;Lcom/squareup/moshi/Moshi$Builder;ILjava/lang/Object;)Ljava/lang/Object;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    invoke-static {}, Lcz/myskoda/api/bff_vehicle_status/v2/infrastructure/Serializer;->getMoshiBuilder()Lcom/squareup/moshi/Moshi$Builder;

    .line 6
    .line 7
    .line 8
    move-result-object p1

    .line 9
    :cond_0
    const-string p2, "<this>"

    .line 10
    .line 11
    const-string p3, "serializerBuilder"

    .line 12
    .line 13
    invoke-static {p0, p2, p1, p3, p1}, Lkx/a;->z(Lretrofit2/Response;Ljava/lang/String;Lcom/squareup/moshi/Moshi$Builder;Ljava/lang/String;Lcom/squareup/moshi/Moshi$Builder;)V

    .line 14
    .line 15
    .line 16
    const/4 p0, 0x0

    .line 17
    throw p0
.end method
