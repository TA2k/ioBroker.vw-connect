.class final enum Lio/opentelemetry/api/baggage/propagation/Parser$State;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/api/baggage/propagation/Parser;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "State"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/api/baggage/propagation/Parser$State;",
        ">;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/api/baggage/propagation/Parser$State;

.field public static final enum KEY:Lio/opentelemetry/api/baggage/propagation/Parser$State;

.field public static final enum META:Lio/opentelemetry/api/baggage/propagation/Parser$State;

.field public static final enum VALUE:Lio/opentelemetry/api/baggage/propagation/Parser$State;


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/api/baggage/propagation/Parser$State;
    .locals 3

    .line 1
    sget-object v0, Lio/opentelemetry/api/baggage/propagation/Parser$State;->KEY:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 2
    .line 3
    sget-object v1, Lio/opentelemetry/api/baggage/propagation/Parser$State;->VALUE:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 4
    .line 5
    sget-object v2, Lio/opentelemetry/api/baggage/propagation/Parser$State;->META:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 6
    .line 7
    filled-new-array {v0, v1, v2}, [Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 2
    .line 3
    const-string v1, "KEY"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/api/baggage/propagation/Parser$State;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/api/baggage/propagation/Parser$State;->KEY:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 10
    .line 11
    new-instance v0, Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 12
    .line 13
    const-string v1, "VALUE"

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/api/baggage/propagation/Parser$State;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Lio/opentelemetry/api/baggage/propagation/Parser$State;->VALUE:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 20
    .line 21
    new-instance v0, Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 22
    .line 23
    const-string v1, "META"

    .line 24
    .line 25
    const/4 v2, 0x2

    .line 26
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/api/baggage/propagation/Parser$State;-><init>(Ljava/lang/String;I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lio/opentelemetry/api/baggage/propagation/Parser$State;->META:Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 30
    .line 31
    invoke-static {}, Lio/opentelemetry/api/baggage/propagation/Parser$State;->$values()[Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    sput-object v0, Lio/opentelemetry/api/baggage/propagation/Parser$State;->$VALUES:[Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 36
    .line 37
    return-void
.end method

.method private constructor <init>(Ljava/lang/String;I)V
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()V"
        }
    .end annotation

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/api/baggage/propagation/Parser$State;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/api/baggage/propagation/Parser$State;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/api/baggage/propagation/Parser$State;->$VALUES:[Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/api/baggage/propagation/Parser$State;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/api/baggage/propagation/Parser$State;

    .line 8
    .line 9
    return-object v0
.end method
