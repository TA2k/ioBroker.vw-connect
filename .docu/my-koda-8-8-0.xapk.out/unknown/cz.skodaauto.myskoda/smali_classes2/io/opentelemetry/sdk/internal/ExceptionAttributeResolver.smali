.class public interface abstract Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver$AttributeSetter;
    }
.end annotation


# static fields
.field public static final EXCEPTION_MESSAGE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field public static final EXCEPTION_STACKTRACE:Lio/opentelemetry/api/common/AttributeKey;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/api/common/AttributeKey<",
            "Ljava/lang/String;",
            ">;"
        }
    .end annotation
.end field

.field public static final EXCEPTION_TYPE:Lio/opentelemetry/api/common/AttributeKey;
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
    const-string v0, "exception.type"

    .line 2
    .line 3
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    sput-object v0, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;->EXCEPTION_TYPE:Lio/opentelemetry/api/common/AttributeKey;

    .line 8
    .line 9
    const-string v0, "exception.message"

    .line 10
    .line 11
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;->EXCEPTION_MESSAGE:Lio/opentelemetry/api/common/AttributeKey;

    .line 16
    .line 17
    const-string v0, "exception.stacktrace"

    .line 18
    .line 19
    invoke-static {v0}, Lio/opentelemetry/api/common/AttributeKey;->stringKey(Ljava/lang/String;)Lio/opentelemetry/api/common/AttributeKey;

    .line 20
    .line 21
    .line 22
    move-result-object v0

    .line 23
    sput-object v0, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;->EXCEPTION_STACKTRACE:Lio/opentelemetry/api/common/AttributeKey;

    .line 24
    .line 25
    return-void
.end method

.method public static getDefault()Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;
    .locals 2

    .line 1
    const-string v0, "otel.experimental.sdk.jvm_stacktrace"

    const-string v1, "false"

    .line 2
    invoke-static {v0, v1}, Lio/opentelemetry/api/internal/ConfigUtil;->getString(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    move-result-object v0

    invoke-static {v0}, Ljava/lang/Boolean;->parseBoolean(Ljava/lang/String;)Z

    move-result v0

    .line 3
    invoke-static {v0}, Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;->getDefault(Z)Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;

    move-result-object v0

    return-object v0
.end method

.method public static getDefault(Z)Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver;
    .locals 1

    .line 4
    new-instance v0, Lio/opentelemetry/sdk/internal/DefaultExceptionAttributeResolver;

    invoke-direct {v0, p0}, Lio/opentelemetry/sdk/internal/DefaultExceptionAttributeResolver;-><init>(Z)V

    return-object v0
.end method


# virtual methods
.method public abstract setExceptionAttributes(Lio/opentelemetry/sdk/internal/ExceptionAttributeResolver$AttributeSetter;Ljava/lang/Throwable;I)V
.end method
