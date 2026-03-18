.class public abstract Lmw0/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Lgv/a;

.field public static final b:Lgv/a;

.field public static final c:Lgv/a;

.field public static final d:Lgv/a;

.field public static final e:Lgv/a;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lgv/a;

    .line 2
    .line 3
    const/16 v1, 0xa

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lgv/a;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lmw0/a;->a:Lgv/a;

    .line 9
    .line 10
    new-instance v0, Lgv/a;

    .line 11
    .line 12
    invoke-direct {v0, v1}, Lgv/a;-><init>(I)V

    .line 13
    .line 14
    .line 15
    sput-object v0, Lmw0/a;->b:Lgv/a;

    .line 16
    .line 17
    new-instance v0, Lgv/a;

    .line 18
    .line 19
    invoke-direct {v0, v1}, Lgv/a;-><init>(I)V

    .line 20
    .line 21
    .line 22
    sput-object v0, Lmw0/a;->c:Lgv/a;

    .line 23
    .line 24
    new-instance v0, Lgv/a;

    .line 25
    .line 26
    invoke-direct {v0, v1}, Lgv/a;-><init>(I)V

    .line 27
    .line 28
    .line 29
    sput-object v0, Lmw0/a;->d:Lgv/a;

    .line 30
    .line 31
    new-instance v0, Lgv/a;

    .line 32
    .line 33
    invoke-direct {v0, v1}, Lgv/a;-><init>(I)V

    .line 34
    .line 35
    .line 36
    sput-object v0, Lmw0/a;->e:Lgv/a;

    .line 37
    .line 38
    return-void
.end method

.method public static final a(Ljava/lang/Throwable;)Ljava/lang/Throwable;
    .locals 3

    .line 1
    const-string v0, "<this>"

    .line 2
    .line 3
    invoke-static {p0, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    move-object v0, p0

    .line 7
    :goto_0
    instance-of v1, v0, Ljava/util/concurrent/CancellationException;

    .line 8
    .line 9
    if-eqz v1, :cond_1

    .line 10
    .line 11
    move-object v1, v0

    .line 12
    check-cast v1, Ljava/util/concurrent/CancellationException;

    .line 13
    .line 14
    invoke-virtual {v1}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 15
    .line 16
    .line 17
    move-result-object v2

    .line 18
    invoke-virtual {v0, v2}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    goto :goto_1

    .line 25
    :cond_0
    invoke-virtual {v1}, Ljava/lang/Throwable;->getCause()Ljava/lang/Throwable;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    goto :goto_0

    .line 30
    :cond_1
    if-nez v0, :cond_2

    .line 31
    .line 32
    :goto_1
    return-object p0

    .line 33
    :cond_2
    return-object v0
.end method
