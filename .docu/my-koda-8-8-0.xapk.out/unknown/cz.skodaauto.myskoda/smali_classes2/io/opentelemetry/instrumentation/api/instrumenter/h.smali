.class public final synthetic Lio/opentelemetry/instrumentation/api/instrumenter/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiConsumer;


# instance fields
.field public final synthetic a:Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/instrumentation/api/instrumenter/h;->a:Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final accept(Ljava/lang/Object;Ljava/lang/Object;)V
    .locals 0

    .line 1
    iget-object p0, p0, Lio/opentelemetry/instrumentation/api/instrumenter/h;->a:Lio/opentelemetry/instrumentation/api/instrumenter/UnsafeAttributes;

    .line 2
    .line 3
    check-cast p1, Lio/opentelemetry/api/common/AttributeKey;

    .line 4
    .line 5
    invoke-virtual {p0, p1, p2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    return-void
.end method
