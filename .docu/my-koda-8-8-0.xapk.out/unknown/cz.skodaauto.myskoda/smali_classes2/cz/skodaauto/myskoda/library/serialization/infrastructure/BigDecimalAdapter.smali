.class public final Lcz/skodaauto/myskoda/library/serialization/infrastructure/BigDecimalAdapter;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0016\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0005\u0018\u00002\u00020\u0001J\u0017\u0010\u0005\u001a\u00020\u00042\u0006\u0010\u0003\u001a\u00020\u0002H\u0007\u00a2\u0006\u0004\u0008\u0005\u0010\u0006J\u0017\u0010\u0007\u001a\u00020\u00022\u0006\u0010\u0003\u001a\u00020\u0004H\u0007\u00a2\u0006\u0004\u0008\u0007\u0010\u0008\u00a8\u0006\t"
    }
    d2 = {
        "Lcz/skodaauto/myskoda/library/serialization/infrastructure/BigDecimalAdapter;",
        "",
        "Ljava/math/BigDecimal;",
        "value",
        "",
        "toJson",
        "(Ljava/math/BigDecimal;)Ljava/lang/String;",
        "fromJson",
        "(Ljava/lang/String;)Ljava/math/BigDecimal;",
        "serialization_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# virtual methods
.method public final fromJson(Ljava/lang/String;)Ljava/math/BigDecimal;
    .locals 0
    .annotation runtime Lcom/squareup/moshi/FromJson;
    .end annotation

    .line 1
    const-string p0, "value"

    .line 2
    .line 3
    invoke-static {p1, p0, p1}, Lkx/a;->q(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/math/BigDecimal;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method

.method public final toJson(Ljava/math/BigDecimal;)Ljava/lang/String;
    .locals 1
    .annotation runtime Lcom/squareup/moshi/ToJson;
    .end annotation

    .line 1
    const-string p0, "value"

    .line 2
    .line 3
    const-string v0, "toPlainString(...)"

    .line 4
    .line 5
    invoke-static {p1, p0, v0}, Lkx/a;->m(Ljava/math/BigDecimal;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
