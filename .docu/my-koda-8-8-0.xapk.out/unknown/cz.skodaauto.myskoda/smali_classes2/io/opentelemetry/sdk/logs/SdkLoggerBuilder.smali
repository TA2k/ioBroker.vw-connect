.class final Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/api/logs/LoggerBuilder;


# instance fields
.field private final instrumentationScopeName:Ljava/lang/String;

.field private instrumentationScopeVersion:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field

.field private final registry:Lio/opentelemetry/sdk/internal/ComponentRegistry;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lio/opentelemetry/sdk/internal/ComponentRegistry<",
            "Lio/opentelemetry/sdk/logs/SdkLogger;",
            ">;"
        }
    .end annotation
.end field

.field private schemaUrl:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method public constructor <init>(Lio/opentelemetry/sdk/internal/ComponentRegistry;Ljava/lang/String;)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Lio/opentelemetry/sdk/internal/ComponentRegistry<",
            "Lio/opentelemetry/sdk/logs/SdkLogger;",
            ">;",
            "Ljava/lang/String;",
            ")V"
        }
    .end annotation

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;->registry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;->instrumentationScopeName:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public bridge synthetic build()Lio/opentelemetry/api/logs/Logger;
    .locals 0

    .line 1
    invoke-virtual {p0}, Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;->build()Lio/opentelemetry/sdk/logs/SdkLogger;

    move-result-object p0

    return-object p0
.end method

.method public build()Lio/opentelemetry/sdk/logs/SdkLogger;
    .locals 4

    .line 2
    iget-object v0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;->registry:Lio/opentelemetry/sdk/internal/ComponentRegistry;

    iget-object v1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;->instrumentationScopeName:Ljava/lang/String;

    iget-object v2, p0, Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;->instrumentationScopeVersion:Ljava/lang/String;

    iget-object p0, p0, Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;->schemaUrl:Ljava/lang/String;

    .line 3
    invoke-static {}, Lio/opentelemetry/api/common/Attributes;->empty()Lio/opentelemetry/api/common/Attributes;

    move-result-object v3

    .line 4
    invoke-virtual {v0, v1, v2, p0, v3}, Lio/opentelemetry/sdk/internal/ComponentRegistry;->get(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Lio/opentelemetry/api/common/Attributes;)Ljava/lang/Object;

    move-result-object p0

    check-cast p0, Lio/opentelemetry/sdk/logs/SdkLogger;

    return-object p0
.end method

.method public bridge synthetic setInstrumentationVersion(Ljava/lang/String;)Lio/opentelemetry/api/logs/LoggerBuilder;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;->setInstrumentationVersion(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setInstrumentationVersion(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;
    .locals 0

    .line 2
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;->instrumentationScopeVersion:Ljava/lang/String;

    return-object p0
.end method

.method public bridge synthetic setSchemaUrl(Ljava/lang/String;)Lio/opentelemetry/api/logs/LoggerBuilder;
    .locals 0

    .line 1
    invoke-virtual {p0, p1}, Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;->setSchemaUrl(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;

    move-result-object p0

    return-object p0
.end method

.method public setSchemaUrl(Ljava/lang/String;)Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;
    .locals 0

    .line 2
    iput-object p1, p0, Lio/opentelemetry/sdk/logs/SdkLoggerBuilder;->schemaUrl:Ljava/lang/String;

    return-object p0
.end method
