.class public final Ltechnology/cariad/cat/genx/GenXError$CoreGenX;
.super Ltechnology/cariad/cat/genx/GenXError;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/GenXError;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "CoreGenX"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000.\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0002\n\u0002\u0010\u0008\n\u0002\u0008\t\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0000\n\u0002\u0008\u0003\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u0017\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0006\u0010\u0007B\u0019\u0008\u0010\u0012\u0006\u0010\u0002\u001a\u00020\u0008\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0004\u0008\u0006\u0010\tJ\t\u0010\u000e\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u000f\u001a\u00020\u0005H\u00c6\u0003J\u001d\u0010\u0010\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0005H\u00c6\u0001J\u0013\u0010\u0011\u001a\u00020\u00122\u0008\u0010\u0013\u001a\u0004\u0018\u00010\u0014H\u00d6\u0003J\t\u0010\u0015\u001a\u00020\u0008H\u00d6\u0001J\t\u0010\u0016\u001a\u00020\u0005H\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u000bR\u0014\u0010\u0004\u001a\u00020\u0005X\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000c\u0010\r\u00a8\u0006\u0017"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/GenXError$CoreGenX;",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "status",
        "Ltechnology/cariad/cat/genx/CoreGenXStatus;",
        "message",
        "",
        "<init>",
        "(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)V",
        "",
        "(ILjava/lang/String;)V",
        "getStatus",
        "()Ltechnology/cariad/cat/genx/CoreGenXStatus;",
        "getMessage",
        "()Ljava/lang/String;",
        "component1",
        "component2",
        "copy",
        "equals",
        "",
        "other",
        "",
        "hashCode",
        "toString",
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
.field private final message:Ljava/lang/String;

.field private final status:Ltechnology/cariad/cat/genx/CoreGenXStatus;


# direct methods
.method public constructor <init>(ILjava/lang/String;)V
    .locals 1

    const-string v0, "message"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    invoke-static {p1}, Ltechnology/cariad/cat/genx/CoreGenXStatusKt;->getCoreGenXStatus(I)Ltechnology/cariad/cat/genx/CoreGenXStatus;

    move-result-object p1

    .line 3
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;-><init>(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)V

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)V
    .locals 1

    const-string v0, "status"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "message"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    .line 1
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/GenXError;-><init>(Lkotlin/jvm/internal/g;)V

    iput-object p1, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->status:Ltechnology/cariad/cat/genx/CoreGenXStatus;

    iput-object p2, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->message:Ljava/lang/String;

    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/genx/GenXError$CoreGenX;Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;ILjava/lang/Object;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;
    .locals 0

    .line 1
    and-int/lit8 p4, p3, 0x1

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->status:Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->message:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->copy(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method


# virtual methods
.method public final component1()Ltechnology/cariad/cat/genx/CoreGenXStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->status:Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->message:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)Ltechnology/cariad/cat/genx/GenXError$CoreGenX;
    .locals 0

    .line 1
    const-string p0, "status"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "message"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 12
    .line 13
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;-><init>(Ltechnology/cariad/cat/genx/CoreGenXStatus;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
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
    instance-of v1, p1, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

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
    check-cast p1, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;

    .line 12
    .line 13
    iget-object v1, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->status:Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 14
    .line 15
    iget-object v3, p1, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->status:Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 16
    .line 17
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-nez v1, :cond_2

    .line 22
    .line 23
    return v2

    .line 24
    :cond_2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->message:Ljava/lang/String;

    .line 25
    .line 26
    iget-object p1, p1, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->message:Ljava/lang/String;

    .line 27
    .line 28
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 29
    .line 30
    .line 31
    move-result p0

    .line 32
    if-nez p0, :cond_3

    .line 33
    .line 34
    return v2

    .line 35
    :cond_3
    return v0
.end method

.method public getMessage()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->message:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getStatus()Ltechnology/cariad/cat/genx/CoreGenXStatus;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->status:Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->status:Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/CoreGenXStatus;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->message:Ljava/lang/String;

    .line 10
    .line 11
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 12
    .line 13
    .line 14
    move-result p0

    .line 15
    add-int/2addr p0, v0

    .line 16
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->status:Ltechnology/cariad/cat/genx/CoreGenXStatus;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$CoreGenX;->message:Ljava/lang/String;

    .line 4
    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "CoreGenX(status="

    .line 8
    .line 9
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 13
    .line 14
    .line 15
    const-string v0, ", message="

    .line 16
    .line 17
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 18
    .line 19
    .line 20
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string p0, ")"

    .line 24
    .line 25
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 29
    .line 30
    .line 31
    move-result-object p0

    .line 32
    return-object p0
.end method
