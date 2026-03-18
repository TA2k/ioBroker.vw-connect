.class public abstract Lio/opentelemetry/instrumentation/api/incubator/semconv/util/ClassAndMethod;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static codeAttributesGetter()Lio/opentelemetry/instrumentation/api/incubator/semconv/code/CodeAttributesGetter;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/code/CodeAttributesGetter<",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/util/ClassAndMethod;",
            ">;"
        }
    .end annotation

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/util/ClassAndMethodAttributesGetter;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/util/ClassAndMethodAttributesGetter;

    .line 2
    .line 3
    return-object v0
.end method

.method public static create(Ljava/lang/Class;Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/util/ClassAndMethod;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/Class<",
            "*>;",
            "Ljava/lang/String;",
            ")",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/util/ClassAndMethod;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/util/AutoValue_ClassAndMethod;

    .line 2
    .line 3
    invoke-direct {v0, p0, p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/util/AutoValue_ClassAndMethod;-><init>(Ljava/lang/Class;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method


# virtual methods
.method public abstract declaringClass()Ljava/lang/Class;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Ljava/lang/Class<",
            "*>;"
        }
    .end annotation
.end method

.method public abstract methodName()Ljava/lang/String;
.end method
