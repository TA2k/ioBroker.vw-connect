.class public Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private final idEnabled:Z

.field private final roleEnabled:Z

.field private final scopeEnabled:Z


# direct methods
.method public constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "instrumentationConfig must not be null"

    .line 5
    .line 6
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    const-string v0, "otel.instrumentation.common.enduser.id.enabled"

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    invoke-interface {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getBoolean(Ljava/lang/String;Z)Z

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;->idEnabled:Z

    .line 17
    .line 18
    const-string v0, "otel.instrumentation.common.enduser.role.enabled"

    .line 19
    .line 20
    invoke-interface {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getBoolean(Ljava/lang/String;Z)Z

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;->roleEnabled:Z

    .line 25
    .line 26
    const-string v0, "otel.instrumentation.common.enduser.scope.enabled"

    .line 27
    .line 28
    invoke-interface {p1, v0, v1}, Lio/opentelemetry/instrumentation/api/incubator/config/internal/InstrumentationConfig;->getBoolean(Ljava/lang/String;Z)Z

    .line 29
    .line 30
    .line 31
    move-result p1

    .line 32
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;->scopeEnabled:Z

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public isAnyEnabled()Z
    .locals 1

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;->idEnabled:Z

    .line 2
    .line 3
    if-nez v0, :cond_1

    .line 4
    .line 5
    iget-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;->roleEnabled:Z

    .line 6
    .line 7
    if-nez v0, :cond_1

    .line 8
    .line 9
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;->scopeEnabled:Z

    .line 10
    .line 11
    if-eqz p0, :cond_0

    .line 12
    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    return p0

    .line 16
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 17
    return p0
.end method

.method public isIdEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;->idEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public isRoleEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;->roleEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public isScopeEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Lio/opentelemetry/instrumentation/api/incubator/config/internal/EnduserConfig;->scopeEnabled:Z

    .line 2
    .line 3
    return p0
.end method
