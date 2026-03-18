.class final Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpMessageBodySizeUtil;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


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

.method private static varargs getAttribute(Lio/opentelemetry/api/common/AttributeKey;[Lio/opentelemetry/api/common/Attributes;)Ljava/lang/Object;
    .locals 3
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<T:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/api/common/AttributeKey<",
            "TT;>;[",
            "Lio/opentelemetry/api/common/Attributes;",
            ")TT;"
        }
    .end annotation

    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    array-length v0, p1

    .line 2
    const/4 v1, 0x0

    .line 3
    :goto_0
    if-ge v1, v0, :cond_1

    .line 4
    .line 5
    aget-object v2, p1, v1

    .line 6
    .line 7
    invoke-interface {v2, p0}, Lio/opentelemetry/api/common/Attributes;->get(Lio/opentelemetry/api/common/AttributeKey;)Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v2

    .line 11
    if-eqz v2, :cond_0

    .line 12
    .line 13
    return-object v2

    .line 14
    :cond_0
    add-int/lit8 v1, v1, 0x1

    .line 15
    .line 16
    goto :goto_0

    .line 17
    :cond_1
    const/4 p0, 0x0

    .line 18
    return-object p0
.end method

.method public static varargs getHttpRequestBodySize([Lio/opentelemetry/api/common/Attributes;)Ljava/lang/Long;
    .locals 1
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpExperimentalAttributesExtractor;->HTTP_REQUEST_BODY_SIZE:Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    invoke-static {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpMessageBodySizeUtil;->getAttribute(Lio/opentelemetry/api/common/AttributeKey;[Lio/opentelemetry/api/common/Attributes;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Long;

    .line 8
    .line 9
    return-object p0
.end method

.method public static varargs getHttpResponseBodySize([Lio/opentelemetry/api/common/Attributes;)Ljava/lang/Long;
    .locals 1
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpExperimentalAttributesExtractor;->HTTP_RESPONSE_BODY_SIZE:Lio/opentelemetry/api/common/AttributeKey;

    .line 2
    .line 3
    invoke-static {v0, p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpMessageBodySizeUtil;->getAttribute(Lio/opentelemetry/api/common/AttributeKey;[Lio/opentelemetry/api/common/Attributes;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ljava/lang/Long;

    .line 8
    .line 9
    return-object p0
.end method
