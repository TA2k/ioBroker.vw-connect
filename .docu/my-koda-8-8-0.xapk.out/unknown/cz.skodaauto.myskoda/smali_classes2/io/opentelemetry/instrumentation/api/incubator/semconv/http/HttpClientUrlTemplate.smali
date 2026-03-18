.class public final Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;
    }
.end annotation


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

.method public static get(Lio/opentelemetry/context/Context;)Ljava/lang/String;
    .locals 0
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;->fromContextOrNull(Lio/opentelemetry/context/Context;)Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;

    .line 2
    .line 3
    .line 4
    move-result-object p0

    .line 5
    if-eqz p0, :cond_0

    .line 6
    .line 7
    invoke-static {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;->access$000(Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0

    .line 12
    :cond_0
    const/4 p0, 0x0

    .line 13
    return-object p0
.end method

.method public static with(Lio/opentelemetry/context/Context;Ljava/lang/String;)Lio/opentelemetry/context/Scope;
    .locals 1

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;

    .line 2
    .line 3
    invoke-direct {v0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p0, v0}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ImplicitContextKeyed;)Lio/opentelemetry/context/Context;

    .line 7
    .line 8
    .line 9
    move-result-object p0

    .line 10
    invoke-interface {p0}, Lio/opentelemetry/context/Context;->makeCurrent()Lio/opentelemetry/context/Scope;

    .line 11
    .line 12
    .line 13
    move-result-object p0

    .line 14
    return-object p0
.end method
