.class public Lnet/zetetic/database/Logger;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final ASSERT:I = 0x7

.field public static final DEBUG:I = 0x3

.field public static final ERROR:I = 0x6

.field public static final INFO:I = 0x4

.field public static final VERBOSE:I = 0x2

.field public static final WARN:I = 0x5

.field private static target:Lnet/zetetic/database/LogTarget;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Lnet/zetetic/database/LogcatTarget;

    .line 2
    .line 3
    invoke-direct {v0}, Lnet/zetetic/database/LogcatTarget;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-static {v0}, Lnet/zetetic/database/Logger;->setTarget(Lnet/zetetic/database/LogTarget;)V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

.method public static d(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-static {}, Lnet/zetetic/database/Logger;->getTarget()Lnet/zetetic/database/LogTarget;

    move-result-object v0

    const/4 v1, 0x3

    const/4 v2, 0x0

    invoke-interface {v0, v1, p0, p1, v2}, Lnet/zetetic/database/LogTarget;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method

.method public static d(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    .locals 2

    .line 2
    invoke-static {}, Lnet/zetetic/database/Logger;->getTarget()Lnet/zetetic/database/LogTarget;

    move-result-object v0

    const/4 v1, 0x3

    invoke-interface {v0, v1, p0, p1, p2}, Lnet/zetetic/database/LogTarget;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method

.method public static e(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-static {}, Lnet/zetetic/database/Logger;->getTarget()Lnet/zetetic/database/LogTarget;

    move-result-object v0

    const/4 v1, 0x6

    const/4 v2, 0x0

    invoke-interface {v0, v1, p0, p1, v2}, Lnet/zetetic/database/LogTarget;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method

.method public static e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    .locals 2

    .line 2
    invoke-static {}, Lnet/zetetic/database/Logger;->getTarget()Lnet/zetetic/database/LogTarget;

    move-result-object v0

    const/4 v1, 0x6

    invoke-interface {v0, v1, p0, p1, p2}, Lnet/zetetic/database/LogTarget;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method

.method private static getTarget()Lnet/zetetic/database/LogTarget;
    .locals 1

    .line 1
    sget-object v0, Lnet/zetetic/database/Logger;->target:Lnet/zetetic/database/LogTarget;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lnet/zetetic/database/NoopTarget;

    .line 6
    .line 7
    invoke-direct {v0}, Lnet/zetetic/database/NoopTarget;-><init>()V

    .line 8
    .line 9
    .line 10
    invoke-static {v0}, Lnet/zetetic/database/Logger;->setTarget(Lnet/zetetic/database/LogTarget;)V

    .line 11
    .line 12
    .line 13
    :cond_0
    sget-object v0, Lnet/zetetic/database/Logger;->target:Lnet/zetetic/database/LogTarget;

    .line 14
    .line 15
    return-object v0
.end method

.method public static i(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-static {}, Lnet/zetetic/database/Logger;->getTarget()Lnet/zetetic/database/LogTarget;

    move-result-object v0

    const/4 v1, 0x4

    const/4 v2, 0x0

    invoke-interface {v0, v1, p0, p1, v2}, Lnet/zetetic/database/LogTarget;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method

.method public static i(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    .locals 2

    .line 2
    invoke-static {}, Lnet/zetetic/database/Logger;->getTarget()Lnet/zetetic/database/LogTarget;

    move-result-object v0

    const/4 v1, 0x4

    invoke-interface {v0, v1, p0, p1, p2}, Lnet/zetetic/database/LogTarget;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method

.method public static isLoggable(Ljava/lang/String;I)Z
    .locals 1

    .line 1
    invoke-static {}, Lnet/zetetic/database/Logger;->getTarget()Lnet/zetetic/database/LogTarget;

    .line 2
    .line 3
    .line 4
    move-result-object v0

    .line 5
    invoke-interface {v0, p0, p1}, Lnet/zetetic/database/LogTarget;->isLoggable(Ljava/lang/String;I)Z

    .line 6
    .line 7
    .line 8
    move-result p0

    .line 9
    return p0
.end method

.method public static setTarget(Lnet/zetetic/database/LogTarget;)V
    .locals 0

    .line 1
    sput-object p0, Lnet/zetetic/database/Logger;->target:Lnet/zetetic/database/LogTarget;

    .line 2
    .line 3
    return-void
.end method

.method public static v(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-static {}, Lnet/zetetic/database/Logger;->getTarget()Lnet/zetetic/database/LogTarget;

    move-result-object v0

    const/4 v1, 0x2

    const/4 v2, 0x0

    invoke-interface {v0, v1, p0, p1, v2}, Lnet/zetetic/database/LogTarget;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method

.method public static v(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    .locals 2

    .line 2
    invoke-static {}, Lnet/zetetic/database/Logger;->getTarget()Lnet/zetetic/database/LogTarget;

    move-result-object v0

    const/4 v1, 0x2

    invoke-interface {v0, v1, p0, p1, p2}, Lnet/zetetic/database/LogTarget;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method

.method public static w(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-static {}, Lnet/zetetic/database/Logger;->getTarget()Lnet/zetetic/database/LogTarget;

    move-result-object v0

    const/4 v1, 0x5

    const/4 v2, 0x0

    invoke-interface {v0, v1, p0, p1, v2}, Lnet/zetetic/database/LogTarget;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method

.method public static w(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    .locals 2

    .line 2
    invoke-static {}, Lnet/zetetic/database/Logger;->getTarget()Lnet/zetetic/database/LogTarget;

    move-result-object v0

    const/4 v1, 0x5

    invoke-interface {v0, v1, p0, p1, p2}, Lnet/zetetic/database/LogTarget;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method

.method public static wtf(Ljava/lang/String;Ljava/lang/String;)V
    .locals 3

    .line 1
    invoke-static {}, Lnet/zetetic/database/Logger;->getTarget()Lnet/zetetic/database/LogTarget;

    move-result-object v0

    const/4 v1, 0x7

    const/4 v2, 0x0

    invoke-interface {v0, v1, p0, p1, v2}, Lnet/zetetic/database/LogTarget;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method

.method public static wtf(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V
    .locals 2

    .line 2
    invoke-static {}, Lnet/zetetic/database/Logger;->getTarget()Lnet/zetetic/database/LogTarget;

    move-result-object v0

    const/4 v1, 0x7

    invoke-interface {v0, v1, p0, p1, p2}, Lnet/zetetic/database/LogTarget;->log(ILjava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)V

    return-void
.end method
