.class abstract Lio/opentelemetry/sdk/trace/data/ImmutableExceptionEventData;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/sdk/trace/data/ExceptionEventData;


# annotations
.annotation build Ljavax/annotation/concurrent/Immutable;
.end annotation


# static fields
.field private static final EXCEPTION_EVENT_NAME:Ljava/lang/String; = "exception"


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

.method public static create(JLjava/lang/Throwable;Lio/opentelemetry/api/common/Attributes;I)Lio/opentelemetry/sdk/trace/data/ExceptionEventData;
    .locals 6

    .line 1
    new-instance v0, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;

    .line 2
    .line 3
    move-wide v2, p0

    .line 4
    move-object v5, p2

    .line 5
    move-object v1, p3

    .line 6
    move v4, p4

    .line 7
    invoke-direct/range {v0 .. v5}, Lio/opentelemetry/sdk/trace/data/AutoValue_ImmutableExceptionEventData;-><init>(Lio/opentelemetry/api/common/Attributes;JILjava/lang/Throwable;)V

    .line 8
    .line 9
    .line 10
    return-object v0
.end method


# virtual methods
.method public final getName()Ljava/lang/String;
    .locals 0

    .line 1
    const-string p0, "exception"

    .line 2
    .line 3
    return-object p0
.end method
