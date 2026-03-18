.class final enum Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;
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
    name = "Eval"
.end annotation

.annotation system Ldalvik/annotation/Signature;
    value = {
        "Ljava/lang/Enum<",
        "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;",
        ">;",
        "Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$CommandSanitizer;"
    }
.end annotation


# static fields
.field private static final synthetic $VALUES:[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;

.field public static final enum INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;


# direct methods
.method private static synthetic $values()[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;

    .line 2
    .line 3
    filled-new-array {v0}, [Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;

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
    new-instance v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;

    .line 2
    .line 3
    const-string v1, "INSTANCE"

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;->INSTANCE:Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;

    .line 10
    .line 11
    invoke-static {}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;->$values()[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;

    .line 12
    .line 13
    .line 14
    move-result-object v0

    .line 15
    sput-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;->$VALUES:[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;

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

.method public static valueOf(Ljava/lang/String;)Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;
    .locals 1

    .line 1
    const-class v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;
    .locals 1

    .line 1
    sget-object v0, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;->$VALUES:[Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;

    .line 2
    .line 3
    invoke-virtual {v0}, [Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer$Eval;

    .line 8
    .line 9
    return-object v0
.end method


# virtual methods
.method public sanitize(Ljava/lang/String;Ljava/util/List;)Ljava/lang/String;
    .locals 3
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
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 7
    .line 8
    .line 9
    move-result p1

    .line 10
    const/4 v0, 0x0

    .line 11
    const/4 v1, 0x2

    .line 12
    if-le p1, v1, :cond_0

    .line 13
    .line 14
    const/4 p1, 0x1

    .line 15
    :try_start_0
    invoke-interface {p2, p1}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p1

    .line 19
    invoke-static {p1}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;->argToString(Ljava/lang/Object;)Ljava/lang/String;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    invoke-static {p1}, Ljava/lang/Integer;->parseInt(Ljava/lang/String;)I

    .line 24
    .line 25
    .line 26
    move-result p1
    :try_end_0
    .catch Ljava/lang/NumberFormatException; {:try_start_0 .. :try_end_0} :catch_0

    .line 27
    goto :goto_0

    .line 28
    :catch_0
    :cond_0
    move p1, v0

    .line 29
    :goto_0
    add-int/lit8 v2, p1, 0x2

    .line 30
    .line 31
    if-ge v0, v2, :cond_1

    .line 32
    .line 33
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 34
    .line 35
    .line 36
    move-result v2

    .line 37
    if-ge v0, v2, :cond_1

    .line 38
    .line 39
    const-string v2, " "

    .line 40
    .line 41
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-interface {p2, v0}, Ljava/util/List;->get(I)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    move-result-object v2

    .line 48
    invoke-static {v2}, Lio/opentelemetry/instrumentation/api/incubator/semconv/db/RedisCommandSanitizer;->argToString(Ljava/lang/Object;)Ljava/lang/String;

    .line 49
    .line 50
    .line 51
    move-result-object v2

    .line 52
    invoke-virtual {p0, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 53
    .line 54
    .line 55
    add-int/lit8 v0, v0, 0x1

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :cond_1
    :goto_1
    invoke-interface {p2}, Ljava/util/List;->size()I

    .line 59
    .line 60
    .line 61
    move-result p1

    .line 62
    if-ge v0, p1, :cond_2

    .line 63
    .line 64
    const-string p1, " ?"

    .line 65
    .line 66
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    add-int/lit8 v0, v0, 0x1

    .line 70
    .line 71
    goto :goto_1

    .line 72
    :cond_2
    invoke-virtual {p0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 73
    .line 74
    .line 75
    move-result-object p0

    .line 76
    return-object p0
.end method
