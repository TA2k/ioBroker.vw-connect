.class Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "UniqueValue"
.end annotation


# instance fields
.field private valid:Z

.field private value:Ljava/lang/String;
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation
.end field


# direct methods
.method private constructor <init>()V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x1

    .line 2
    iput-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;->valid:Z

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$1;)V
    .locals 0

    .line 3
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;-><init>()V

    return-void
.end method


# virtual methods
.method public getValue()Ljava/lang/String;
    .locals 1
    .annotation runtime Ljavax/annotation/Nullable;
    .end annotation

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;->valid:Z

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;->value:Ljava/lang/String;

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    const/4 p0, 0x0

    .line 9
    return-object p0
.end method

.method public set(Ljava/lang/String;)V
    .locals 1
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    iget-boolean v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;->valid:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    goto :goto_0

    .line 6
    :cond_0
    iget-object v0, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;->value:Ljava/lang/String;

    .line 7
    .line 8
    if-nez v0, :cond_1

    .line 9
    .line 10
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;->value:Ljava/lang/String;

    .line 11
    .line 12
    return-void

    .line 13
    :cond_1
    invoke-virtual {v0, p1}, Ljava/lang/String;->equals(Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result p1

    .line 17
    if-nez p1, :cond_2

    .line 18
    .line 19
    const/4 p1, 0x0

    .line 20
    iput-boolean p1, p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/MultiQuery$UniqueValue;->valid:Z

    .line 21
    .line 22
    :cond_2
    :goto_0
    return-void
.end method
