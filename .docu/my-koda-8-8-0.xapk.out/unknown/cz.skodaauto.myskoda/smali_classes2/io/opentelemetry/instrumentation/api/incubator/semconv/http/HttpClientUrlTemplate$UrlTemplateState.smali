.class Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/context/ImplicitContextKeyed;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "UrlTemplateState"
.end annotation


# static fields
.field private static final KEY:Lio/opentelemetry/context/ContextKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/context/ContextKey<",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field private final urlTemplate:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "opentelemetry-http-client-url-template-key"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/context/ContextKey;->named(Ljava/lang/String;)Lio/opentelemetry/context/ContextKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;->urlTemplate:Ljava/lang/String;

    .line 5
    .line 6
    return-void
.end method

.method public static synthetic access$000(Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;)Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;->urlTemplate:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public static fromContextOrNull(Lio/opentelemetry/context/Context;)Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;
    .locals 1
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p0, v0}, Lio/opentelemetry/context/Context;->get(Lio/opentelemetry/context/ContextKey;)Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;

    .line 8
    .line 9
    return-object p0
.end method


# virtual methods
.method public storeInContext(Lio/opentelemetry/context/Context;)Lio/opentelemetry/context/Context;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/http/HttpClientUrlTemplate$UrlTemplateState;->KEY:Lio/opentelemetry/context/ContextKey;

    .line 2
    .line 3
    invoke-interface {p1, v0, p0}, Lio/opentelemetry/context/Context;->with(Lio/opentelemetry/context/ContextKey;Ljava/lang/Object;)Lio/opentelemetry/context/Context;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    return-object p0
.end method
