.class public final Lnet/zetetic/database/sqlcipher/CloseGuard;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Lnet/zetetic/database/sqlcipher/CloseGuard$Reporter;,
        Lnet/zetetic/database/sqlcipher/CloseGuard$DefaultReporter;
    }
.end annotation


# static fields
.field private static volatile ENABLED:Z

.field private static final NOOP:Lnet/zetetic/database/sqlcipher/CloseGuard;

.field private static volatile REPORTER:Lnet/zetetic/database/sqlcipher/CloseGuard$Reporter;


# instance fields
.field private allocationSite:Ljava/lang/Throwable;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 2
    .line 3
    invoke-direct {v0}, Lnet/zetetic/database/sqlcipher/CloseGuard;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lnet/zetetic/database/sqlcipher/CloseGuard;->NOOP:Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 7
    .line 8
    const/4 v0, 0x1

    .line 9
    sput-boolean v0, Lnet/zetetic/database/sqlcipher/CloseGuard;->ENABLED:Z

    .line 10
    .line 11
    new-instance v0, Lnet/zetetic/database/sqlcipher/CloseGuard$DefaultReporter;

    .line 12
    .line 13
    const/4 v1, 0x0

    .line 14
    invoke-direct {v0, v1}, Lnet/zetetic/database/sqlcipher/CloseGuard$DefaultReporter;-><init>(I)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lnet/zetetic/database/sqlcipher/CloseGuard;->REPORTER:Lnet/zetetic/database/sqlcipher/CloseGuard$Reporter;

    .line 18
    .line 19
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

.method public static get()Lnet/zetetic/database/sqlcipher/CloseGuard;
    .locals 1

    .line 1
    sget-boolean v0, Lnet/zetetic/database/sqlcipher/CloseGuard;->ENABLED:Z

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    sget-object v0, Lnet/zetetic/database/sqlcipher/CloseGuard;->NOOP:Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 6
    .line 7
    return-object v0

    .line 8
    :cond_0
    new-instance v0, Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 9
    .line 10
    invoke-direct {v0}, Lnet/zetetic/database/sqlcipher/CloseGuard;-><init>()V

    .line 11
    .line 12
    .line 13
    return-object v0
.end method

.method public static getReporter()Lnet/zetetic/database/sqlcipher/CloseGuard$Reporter;
    .locals 1

    .line 1
    sget-object v0, Lnet/zetetic/database/sqlcipher/CloseGuard;->REPORTER:Lnet/zetetic/database/sqlcipher/CloseGuard$Reporter;

    .line 2
    .line 3
    return-object v0
.end method

.method public static setEnabled(Z)V
    .locals 0

    .line 1
    sput-boolean p0, Lnet/zetetic/database/sqlcipher/CloseGuard;->ENABLED:Z

    .line 2
    .line 3
    return-void
.end method

.method public static setReporter(Lnet/zetetic/database/sqlcipher/CloseGuard$Reporter;)V
    .locals 1

    .line 1
    if-eqz p0, :cond_0

    .line 2
    .line 3
    sput-object p0, Lnet/zetetic/database/sqlcipher/CloseGuard;->REPORTER:Lnet/zetetic/database/sqlcipher/CloseGuard$Reporter;

    .line 4
    .line 5
    return-void

    .line 6
    :cond_0
    new-instance p0, Ljava/lang/NullPointerException;

    .line 7
    .line 8
    const-string v0, "reporter == null"

    .line 9
    .line 10
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    throw p0
.end method


# virtual methods
.method public close()V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/CloseGuard;->allocationSite:Ljava/lang/Throwable;

    .line 3
    .line 4
    return-void
.end method

.method public open(Ljava/lang/String;)V
    .locals 2

    .line 1
    if-eqz p1, :cond_2

    .line 2
    .line 3
    sget-object v0, Lnet/zetetic/database/sqlcipher/CloseGuard;->NOOP:Lnet/zetetic/database/sqlcipher/CloseGuard;

    .line 4
    .line 5
    if-eq p0, v0, :cond_1

    .line 6
    .line 7
    sget-boolean v0, Lnet/zetetic/database/sqlcipher/CloseGuard;->ENABLED:Z

    .line 8
    .line 9
    if-nez v0, :cond_0

    .line 10
    .line 11
    goto :goto_0

    .line 12
    :cond_0
    const-string v0, "Explicit termination method \'"

    .line 13
    .line 14
    const-string v1, "\' not called"

    .line 15
    .line 16
    invoke-static {v0, p1, v1}, Lp3/m;->j(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 17
    .line 18
    .line 19
    move-result-object p1

    .line 20
    new-instance v0, Ljava/lang/Throwable;

    .line 21
    .line 22
    invoke-direct {v0, p1}, Ljava/lang/Throwable;-><init>(Ljava/lang/String;)V

    .line 23
    .line 24
    .line 25
    iput-object v0, p0, Lnet/zetetic/database/sqlcipher/CloseGuard;->allocationSite:Ljava/lang/Throwable;

    .line 26
    .line 27
    :cond_1
    :goto_0
    return-void

    .line 28
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 29
    .line 30
    const-string p1, "closer == null"

    .line 31
    .line 32
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    throw p0
.end method

.method public warnIfOpen()V
    .locals 2

    .line 1
    iget-object v0, p0, Lnet/zetetic/database/sqlcipher/CloseGuard;->allocationSite:Ljava/lang/Throwable;

    .line 2
    .line 3
    if-eqz v0, :cond_1

    .line 4
    .line 5
    sget-boolean v0, Lnet/zetetic/database/sqlcipher/CloseGuard;->ENABLED:Z

    .line 6
    .line 7
    if-nez v0, :cond_0

    .line 8
    .line 9
    goto :goto_0

    .line 10
    :cond_0
    sget-object v0, Lnet/zetetic/database/sqlcipher/CloseGuard;->REPORTER:Lnet/zetetic/database/sqlcipher/CloseGuard$Reporter;

    .line 11
    .line 12
    iget-object p0, p0, Lnet/zetetic/database/sqlcipher/CloseGuard;->allocationSite:Ljava/lang/Throwable;

    .line 13
    .line 14
    const-string v1, "A resource was acquired at attached stack trace but never released. See java.io.Closeable for information on avoiding resource leaks."

    .line 15
    .line 16
    invoke-interface {v0, v1, p0}, Lnet/zetetic/database/sqlcipher/CloseGuard$Reporter;->report(Ljava/lang/String;Ljava/lang/Throwable;)V

    .line 17
    .line 18
    .line 19
    :cond_1
    :goto_0
    return-void
.end method
