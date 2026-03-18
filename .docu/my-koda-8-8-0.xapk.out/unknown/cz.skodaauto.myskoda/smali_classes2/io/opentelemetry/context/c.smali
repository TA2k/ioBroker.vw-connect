.class public final synthetic Lio/opentelemetry/context/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/BiFunction;


# instance fields
.field public final synthetic a:Lio/opentelemetry/context/Context;

.field public final synthetic b:Ljava/util/function/BiFunction;


# direct methods
.method public synthetic constructor <init>(Lio/opentelemetry/context/Context;Ljava/util/function/BiFunction;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lio/opentelemetry/context/c;->a:Lio/opentelemetry/context/Context;

    .line 5
    .line 6
    iput-object p2, p0, Lio/opentelemetry/context/c;->b:Ljava/util/function/BiFunction;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final apply(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Lio/opentelemetry/context/c;->a:Lio/opentelemetry/context/Context;

    .line 2
    .line 3
    iget-object p0, p0, Lio/opentelemetry/context/c;->b:Ljava/util/function/BiFunction;

    .line 4
    .line 5
    invoke-static {v0, p0, p1, p2}, Lio/opentelemetry/context/Context;->b(Lio/opentelemetry/context/Context;Ljava/util/function/BiFunction;Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 6
    .line 7
    .line 8
    move-result-object p0

    .line 9
    return-object p0
.end method
