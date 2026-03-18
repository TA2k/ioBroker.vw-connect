.class final enum Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter$2;
.super Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4011
    name = null
.end annotation


# direct methods
.method public constructor <init>(Ljava/lang/String;I)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, p2, v0}, Lio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter;-><init>(Ljava/lang/String;ILio/opentelemetry/instrumentation/api/semconv/http/HttpStatusCodeConverter$1;)V

    .line 3
    .line 4
    .line 5
    return-void
.end method


# virtual methods
.method public isError(I)Z
    .locals 0

    .line 1
    const/16 p0, 0x190

    .line 2
    .line 3
    if-ge p1, p0, :cond_1

    .line 4
    .line 5
    const/16 p0, 0x64

    .line 6
    .line 7
    if-ge p1, p0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    const/4 p0, 0x0

    .line 11
    return p0

    .line 12
    :cond_1
    :goto_0
    const/4 p0, 0x1

    .line 13
    return p0
.end method
