.class public final Lio/opentelemetry/semconv/HttpAttributes;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/semconv/HttpAttributes$HttpRequestMethodValues;
    }
.end annotation


# static fields
.field public static final HTTP_REQUEST_HEADER:Lio/opentelemetry/semconv/AttributeKeyTemplate;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/semconv/AttributeKeyTemplate<",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation
.end field

.field public static final HTTP_REQUEST_METHOD:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field public static final HTTP_REQUEST_METHOD_ORIGINAL:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field public static final HTTP_REQUEST_RESEND_COUNT:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field public static final HTTP_RESPONSE_HEADER:Lio/opentelemetry/semconv/AttributeKeyTemplate;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/semconv/AttributeKeyTemplate<",
            "Ljava/util/List<",
            "Ljava/lang/String;",
            ">;>;"
        }
    .end annotation
.end field

.field public static final HTTP_RESPONSE_STATUS_CODE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/Long;",
            ">;"
        }
    .end annotation
.end field

.field public static final HTTP_ROUTE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    const-string v0, "http.request.header"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/semconv/AttributeKeyTemplate;->stringArrayKeyTemplate(Ljava/lang/String;)Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_REQUEST_HEADER:Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 8
    .line 9
    const-string v0, "http.request.method"

    .line 10
    .line 11
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_REQUEST_METHOD:Lio/opentelemetry/api/common/AttributeKey;

    .line 16
    .line 17
    const-string v0, "http.request.method_original"

    .line 18
    .line 19
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_REQUEST_METHOD_ORIGINAL:Lio/opentelemetry/api/common/AttributeKey;

    .line 24
    .line 25
    const-string v0, "http.request.resend_count"

    .line 26
    .line 27
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    sput-object v0, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_REQUEST_RESEND_COUNT:Lio/opentelemetry/api/common/AttributeKey;

    .line 32
    .line 33
    const-string v0, "http.response.header"

    .line 34
    .line 35
    invoke-static {v0}, Lio/opentelemetry/semconv/AttributeKeyTemplate;->stringArrayKeyTemplate(Ljava/lang/String;)Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 36
    .line 37
    .line 38
    move-result-object v0

    .line 39
    sput-object v0, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_RESPONSE_HEADER:Lio/opentelemetry/semconv/AttributeKeyTemplate;

    .line 40
    .line 41
    const-string v0, "http.response.status_code"

    .line 42
    .line 43
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->longKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 44
    .line 45
    .line 46
    move-result-object v0

    .line 47
    sput-object v0, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_RESPONSE_STATUS_CODE:Lio/opentelemetry/api/common/AttributeKey;

    .line 48
    .line 49
    const-string v0, "http.route"

    .line 50
    .line 51
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 52
    .line 53
    .line 54
    move-result-object v0

    .line 55
    sput-object v0, Lio/opentelemetry/semconv/HttpAttributes;->HTTP_ROUTE:Lio/opentelemetry/api/common/AttributeKey;

    .line 56
    .line 57
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method
