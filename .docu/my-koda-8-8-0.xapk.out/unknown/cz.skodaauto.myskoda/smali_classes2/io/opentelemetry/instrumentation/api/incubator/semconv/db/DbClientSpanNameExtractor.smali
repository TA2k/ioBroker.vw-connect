.class public abstract Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$GenericDbClientSpanNameExtractor;,
        Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$SqlClientSpanNameExtractor;
    }
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "<REQUEST:",
        "Ljava/lang/Object;",
        ">",
        "Ljava/lang/Object;",
        "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
        "TREQUEST;>;"
    }
.end annotation


# static fields
.field private static final DEFAULT_SPAN_NAME:Ljava/lang/String; = "DB Query"


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$1;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor;-><init>()V

    return-void
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter<",
            "TREQUEST;*>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$GenericDbClientSpanNameExtractor;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$GenericDbClientSpanNameExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$1;)V

    return-object v0
.end method

.method public static create(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;)Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor;
    .locals 2
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "<REQUEST:",
            "Ljava/lang/Object;",
            ">(",
            "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter<",
            "TREQUEST;*>;)",
            "Lio/opentelemetry/instrumentation/api/instrumenter/SpanNameExtractor<",
            "TREQUEST;>;"
        }
    .end annotation

    .line 2
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$SqlClientSpanNameExtractor;

    const/4 v1, 0x0

    invoke-direct {v0, p0, v1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$SqlClientSpanNameExtractor;-><init>(Lio/opentelemetry/instrumentation/api/incubator/semconv/db/SqlClientAttributesGetter;Lio/opentelemetry/instrumentation/api/incubator/semconv/db/DbClientSpanNameExtractor$1;)V

    return-object v0
.end method


# virtual methods
.method public computeSpanName(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;
    .locals 2
    .param p1    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p2    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param
    .param p3    # Ljava/lang/String;
        .annotation runtime Ljavax/annotation/Nullable;
        .end annotation
    .end param

    .line 1
    if-nez p2, :cond_1

    .line 2
    .line 3
    if-nez p1, :cond_0

    .line 4
    .line 5
    const-string p0, "DB Query"

    .line 6
    .line 7
    return-object p0

    .line 8
    :cond_0
    return-object p1

    .line 9
    :cond_1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    invoke-direct {p0, p2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    if-nez p1, :cond_2

    .line 15
    .line 16
    if-eqz p3, :cond_3

    .line 17
    .line 18
    :cond_2
    const/16 p2, 0x20

    .line 19
    .line 20
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    :cond_3
    if-eqz p1, :cond_5

    .line 24
    .line 25
    const/16 p2, 0x2e

    .line 26
    .line 27
    if-eqz p3, :cond_4

    .line 28
    .line 29
    invoke-virtual {p3, p2}, Ljava/lang/String;->indexOf(I)I

    .line 30
    .line 31
    .line 32
    move-result v0

    .line 33
    const/4 v1, -0x1

    .line 34
    if-ne v0, v1, :cond_5

    .line 35
    .line 36
    :cond_4
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    if-eqz p3, :cond_5

    .line 40
    .line 41
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    :cond_5
    if-eqz p3, :cond_6

    .line 45
    .line 46
    invoke-virtual {p0, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    :cond_6
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 50
    .line 51
    .line 52
    move-result-object p0

    .line 53
    return-object p0
.end method
