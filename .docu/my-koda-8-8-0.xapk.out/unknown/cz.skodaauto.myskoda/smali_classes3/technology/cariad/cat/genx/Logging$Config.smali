.class public final Ltechnology/cariad/cat/genx/Logging$Config;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/Logging;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Config"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0018\u0002\n\u0002\u0008\r\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\t\u0008\u0086\u0008\u0018\u00002\u00020\u0001B/\u0012\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0004\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0002\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u0010\u0010\n\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008\n\u0010\u000bJ\u0010\u0010\u000c\u001a\u00020\u0004H\u00c6\u0003\u00a2\u0006\u0004\u0008\u000c\u0010\rJ\u0010\u0010\u000e\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008\u000e\u0010\u000bJ\u0010\u0010\u000f\u001a\u00020\u0002H\u00c6\u0003\u00a2\u0006\u0004\u0008\u000f\u0010\u000bJ8\u0010\u0010\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0003\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00042\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u00022\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0002H\u00c6\u0001\u00a2\u0006\u0004\u0008\u0010\u0010\u0011J\u0010\u0010\u0013\u001a\u00020\u0012H\u00d6\u0001\u00a2\u0006\u0004\u0008\u0013\u0010\u0014J\u0010\u0010\u0016\u001a\u00020\u0015H\u00d6\u0001\u00a2\u0006\u0004\u0008\u0016\u0010\u0017J\u001a\u0010\u0019\u001a\u00020\u00022\u0008\u0010\u0018\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003\u00a2\u0006\u0004\u0008\u0019\u0010\u001aR\u0017\u0010\u0003\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0003\u0010\u001b\u001a\u0004\u0008\u0003\u0010\u000bR\u0017\u0010\u0005\u001a\u00020\u00048\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0005\u0010\u001c\u001a\u0004\u0008\u001d\u0010\rR\u0017\u0010\u0006\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0006\u0010\u001b\u001a\u0004\u0008\u0006\u0010\u000bR\u0017\u0010\u0007\u001a\u00020\u00028\u0006\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010\u001b\u001a\u0004\u0008\u0007\u0010\u000b\u00a8\u0006\u001e"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/Logging$Config;",
        "",
        "",
        "isCoreGenXLoggingEnabled",
        "Lt51/i;",
        "minimumCoreGenXLogLevel",
        "isJNILoggingEnabled",
        "isScanResponseLoggingEnabled",
        "<init>",
        "(ZLt51/i;ZZ)V",
        "component1",
        "()Z",
        "component2",
        "()Lt51/i;",
        "component3",
        "component4",
        "copy",
        "(ZLt51/i;ZZ)Ltechnology/cariad/cat/genx/Logging$Config;",
        "",
        "toString",
        "()Ljava/lang/String;",
        "",
        "hashCode",
        "()I",
        "other",
        "equals",
        "(Ljava/lang/Object;)Z",
        "Z",
        "Lt51/i;",
        "getMinimumCoreGenXLogLevel",
        "genx_release"
    }
    k = 0x1
    mv = {
        0x2,
        0x2,
        0x0
    }
    xi = 0x30
.end annotation


# instance fields
.field private final isCoreGenXLoggingEnabled:Z

.field private final isJNILoggingEnabled:Z

.field private final isScanResponseLoggingEnabled:Z

.field private final minimumCoreGenXLogLevel:Lt51/i;


# direct methods
.method public constructor <init>()V
    .locals 7

    .line 1
    const/16 v5, 0xf

    const/4 v6, 0x0

    const/4 v1, 0x0

    const/4 v2, 0x0

    const/4 v3, 0x0

    const/4 v4, 0x0

    move-object v0, p0

    invoke-direct/range {v0 .. v6}, Ltechnology/cariad/cat/genx/Logging$Config;-><init>(ZLt51/i;ZZILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(ZLt51/i;ZZ)V
    .locals 1

    const-string v0, "minimumCoreGenXLogLevel"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-boolean p1, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isCoreGenXLoggingEnabled:Z

    .line 4
    iput-object p2, p0, Ltechnology/cariad/cat/genx/Logging$Config;->minimumCoreGenXLogLevel:Lt51/i;

    .line 5
    iput-boolean p3, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isJNILoggingEnabled:Z

    .line 6
    iput-boolean p4, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isScanResponseLoggingEnabled:Z

    return-void
.end method

.method public synthetic constructor <init>(ZLt51/i;ZZILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p6, p5, 0x1

    const/4 v0, 0x0

    if-eqz p6, :cond_0

    move p1, v0

    :cond_0
    and-int/lit8 p6, p5, 0x2

    if-eqz p6, :cond_1

    .line 7
    sget-object p2, Lt51/d;->a:Lt51/d;

    :cond_1
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_2

    move p3, v0

    :cond_2
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_3

    move p4, v0

    .line 8
    :cond_3
    invoke-direct {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/Logging$Config;-><init>(ZLt51/i;ZZ)V

    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/genx/Logging$Config;ZLt51/i;ZZILjava/lang/Object;)Ltechnology/cariad/cat/genx/Logging$Config;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-boolean p1, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isCoreGenXLoggingEnabled:Z

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Ltechnology/cariad/cat/genx/Logging$Config;->minimumCoreGenXLogLevel:Lt51/i;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-boolean p3, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isJNILoggingEnabled:Z

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-boolean p4, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isScanResponseLoggingEnabled:Z

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/Logging$Config;->copy(ZLt51/i;ZZ)Ltechnology/cariad/cat/genx/Logging$Config;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method


# virtual methods
.method public final component1()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isCoreGenXLoggingEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Lt51/i;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->minimumCoreGenXLogLevel:Lt51/i;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isJNILoggingEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component4()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isScanResponseLoggingEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final copy(ZLt51/i;ZZ)Ltechnology/cariad/cat/genx/Logging$Config;
    .locals 0

    .line 1
    const-string p0, "minimumCoreGenXLogLevel"

    .line 2
    .line 3
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ltechnology/cariad/cat/genx/Logging$Config;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/Logging$Config;-><init>(ZLt51/i;ZZ)V

    .line 9
    .line 10
    .line 11
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/genx/Logging$Config;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Ltechnology/cariad/cat/genx/Logging$Config;

    .line 12
    .line 13
    iget-boolean v1, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isCoreGenXLoggingEnabled:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Ltechnology/cariad/cat/genx/Logging$Config;->isCoreGenXLoggingEnabled:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object v1, p0, Ltechnology/cariad/cat/genx/Logging$Config;->minimumCoreGenXLogLevel:Lt51/i;

    .line 21
    .line 22
    iget-object v3, p1, Ltechnology/cariad/cat/genx/Logging$Config;->minimumCoreGenXLogLevel:Lt51/i;

    .line 23
    .line 24
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result v1

    .line 28
    if-nez v1, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    iget-boolean v1, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isJNILoggingEnabled:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Ltechnology/cariad/cat/genx/Logging$Config;->isJNILoggingEnabled:Z

    .line 34
    .line 35
    if-eq v1, v3, :cond_4

    .line 36
    .line 37
    return v2

    .line 38
    :cond_4
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isScanResponseLoggingEnabled:Z

    .line 39
    .line 40
    iget-boolean p1, p1, Ltechnology/cariad/cat/genx/Logging$Config;->isScanResponseLoggingEnabled:Z

    .line 41
    .line 42
    if-eq p0, p1, :cond_5

    .line 43
    .line 44
    return v2

    .line 45
    :cond_5
    return v0
.end method

.method public final getMinimumCoreGenXLogLevel()Lt51/i;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->minimumCoreGenXLogLevel:Lt51/i;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isCoreGenXLoggingEnabled:Z

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/16 v1, 0x1f

    .line 8
    .line 9
    mul-int/2addr v0, v1

    .line 10
    iget-object v2, p0, Ltechnology/cariad/cat/genx/Logging$Config;->minimumCoreGenXLogLevel:Lt51/i;

    .line 11
    .line 12
    invoke-virtual {v2}, Ljava/lang/Object;->hashCode()I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    add-int/2addr v2, v0

    .line 17
    mul-int/2addr v2, v1

    .line 18
    iget-boolean v0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isJNILoggingEnabled:Z

    .line 19
    .line 20
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isScanResponseLoggingEnabled:Z

    .line 25
    .line 26
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    add-int/2addr p0, v0

    .line 31
    return p0
.end method

.method public final isCoreGenXLoggingEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isCoreGenXLoggingEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isJNILoggingEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isJNILoggingEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public final isScanResponseLoggingEnabled()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isScanResponseLoggingEnabled:Z

    .line 2
    .line 3
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isCoreGenXLoggingEnabled:Z

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/Logging$Config;->minimumCoreGenXLogLevel:Lt51/i;

    .line 4
    .line 5
    iget-boolean v2, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isJNILoggingEnabled:Z

    .line 6
    .line 7
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/Logging$Config;->isScanResponseLoggingEnabled:Z

    .line 8
    .line 9
    new-instance v3, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v4, "Config(isCoreGenXLoggingEnabled="

    .line 12
    .line 13
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 17
    .line 18
    .line 19
    const-string v0, ", minimumCoreGenXLogLevel="

    .line 20
    .line 21
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 22
    .line 23
    .line 24
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    const-string v0, ", isJNILoggingEnabled="

    .line 28
    .line 29
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 30
    .line 31
    .line 32
    const-string v0, ", isScanResponseLoggingEnabled="

    .line 33
    .line 34
    const-string v1, ")"

    .line 35
    .line 36
    invoke-static {v3, v2, v0, p0, v1}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 37
    .line 38
    .line 39
    move-result-object p0

    .line 40
    return-object p0
.end method
