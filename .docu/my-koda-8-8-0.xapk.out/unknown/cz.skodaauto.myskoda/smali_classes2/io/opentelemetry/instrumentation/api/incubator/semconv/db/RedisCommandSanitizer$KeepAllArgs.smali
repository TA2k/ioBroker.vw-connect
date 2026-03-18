.class final enum Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandSanitizer;


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x4019
    name = "KeepAllArgs"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;",
        ">;",
        "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandSanitizer;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

.field public static final enum INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 2
    .line 3
    filled-new-array {v0}, [Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    return-object v0
.end method

.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 2
    .line 3
    const-string v1, "INSTANCE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->$values()[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->$VALUES:[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 16
    .line 17
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

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->$VALUES:[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$KeepAllArgs;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public sanitize(Ljava/lang/String;Ljava/util/List;)Ljava/lang/String;
    .locals 1
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "(",
            "Ljava/lang/String;",
            "Ljava/util/List<",
            "*>;)",
            "Ljava/lang/String;"
        }
    .end annotation

    .line 1
    new-instance p0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-interface {p2}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 7
    .line 8
    .line 9
    move-result-object p1

    .line 10
    :goto_0
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 11
    .line 12
    .line 13
    move-result p2

    .line 14
    if-eqz p2, :cond_0

    .line 15
    .line 16
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    move-result-object p2

    .line 20
    const-string v0, " "

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-static {p2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;->argToString(Ljava/lang/Object;)Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object p2

    .line 29
    invoke-virtual {p0, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    goto :goto_0

    .line 33
    :cond_0
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method
