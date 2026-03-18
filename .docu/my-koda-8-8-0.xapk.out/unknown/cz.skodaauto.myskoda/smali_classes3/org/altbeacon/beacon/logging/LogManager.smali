.class public final Lorg/altbeacon/beacon/logging/LogManager;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field private static sLogger:Lorg/altbeacon/beacon/logging/Logger;

.field private static sVerboseLoggingEnabled:Z


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    invoke-static {}, Lorg/altbeacon/beacon/logging/Loggers;->infoLogger()Lorg/altbeacon/beacon/logging/Logger;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    sput-object v0, Lorg/altbeacon/beacon/logging/LogManager;->sLogger:Lorg/altbeacon/beacon/logging/Logger;

    .line 6
    .line 7
    const/4 v0, 0x0

    .line 8
    sput-boolean v0, Lorg/altbeacon/beacon/logging/LogManager;->sVerboseLoggingEnabled:Z

    .line 9
    .line 10
    return-void
.end method

.method private constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static varargs d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/logging/LogManager;->sLogger:Lorg/altbeacon/beacon/logging/Logger;

    invoke-interface {v0, p0, p1, p2}, Lorg/altbeacon/beacon/logging/Logger;->d(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public static varargs d(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    .line 2
    sget-object v0, Lorg/altbeacon/beacon/logging/LogManager;->sLogger:Lorg/altbeacon/beacon/logging/Logger;

    invoke-interface {v0, p0, p1, p2, p3}, Lorg/altbeacon/beacon/logging/Logger;->d(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public static varargs e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/logging/LogManager;->sLogger:Lorg/altbeacon/beacon/logging/Logger;

    invoke-interface {v0, p0, p1, p2}, Lorg/altbeacon/beacon/logging/Logger;->e(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public static varargs e(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    .line 2
    sget-object v0, Lorg/altbeacon/beacon/logging/LogManager;->sLogger:Lorg/altbeacon/beacon/logging/Logger;

    invoke-interface {v0, p0, p1, p2, p3}, Lorg/altbeacon/beacon/logging/Logger;->e(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public static getLogger()Lorg/altbeacon/beacon/logging/Logger;
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/logging/LogManager;->sLogger:Lorg/altbeacon/beacon/logging/Logger;

    .line 2
    .line 3
    return-object v0
.end method

.method public static varargs i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/logging/LogManager;->sLogger:Lorg/altbeacon/beacon/logging/Logger;

    invoke-interface {v0, p0, p1, p2}, Lorg/altbeacon/beacon/logging/Logger;->i(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public static varargs i(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    .line 2
    sget-object v0, Lorg/altbeacon/beacon/logging/LogManager;->sLogger:Lorg/altbeacon/beacon/logging/Logger;

    invoke-interface {v0, p0, p1, p2, p3}, Lorg/altbeacon/beacon/logging/Logger;->i(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public static isVerboseLoggingEnabled()Z
    .locals 1

    .line 1
    sget-boolean v0, Lorg/altbeacon/beacon/logging/LogManager;->sVerboseLoggingEnabled:Z

    .line 2
    .line 3
    return v0
.end method

.method public static setLogger(Lorg/altbeacon/beacon/logging/Logger;)V
    .locals 1

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    sput-object p0, Lorg/altbeacon/beacon/logging/LogManager;->sLogger:Lorg/altbeacon/beacon/logging/Logger;

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 7
    .line 8
    const-string v0, "Logger may not be null."

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method

.method public static setVerboseLoggingEnabled(Z)V
    .locals 0

    .line 1
    sput-boolean p0, Lorg/altbeacon/beacon/logging/LogManager;->sVerboseLoggingEnabled:Z

    .line 2
    .line 3
    return-void
.end method

.method public static varargs v(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/logging/LogManager;->sLogger:Lorg/altbeacon/beacon/logging/Logger;

    invoke-interface {v0, p0, p1, p2}, Lorg/altbeacon/beacon/logging/Logger;->v(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public static varargs v(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    .line 2
    sget-object v0, Lorg/altbeacon/beacon/logging/LogManager;->sLogger:Lorg/altbeacon/beacon/logging/Logger;

    invoke-interface {v0, p0, p1, p2, p3}, Lorg/altbeacon/beacon/logging/Logger;->v(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public static varargs w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    .line 1
    sget-object v0, Lorg/altbeacon/beacon/logging/LogManager;->sLogger:Lorg/altbeacon/beacon/logging/Logger;

    invoke-interface {v0, p0, p1, p2}, Lorg/altbeacon/beacon/logging/Logger;->w(Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method

.method public static varargs w(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V
    .locals 1

    .line 2
    sget-object v0, Lorg/altbeacon/beacon/logging/LogManager;->sLogger:Lorg/altbeacon/beacon/logging/Logger;

    invoke-interface {v0, p0, p1, p2, p3}, Lorg/altbeacon/beacon/logging/Logger;->w(Ljava/lang/Throwable;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/Object;)V

    return-void
.end method
