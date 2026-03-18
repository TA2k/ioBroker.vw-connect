.class public final Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;
.super Ltechnology/cariad/cat/genx/GenXError;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/genx/GenXError;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ConnectNotAllowed"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000,\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\n\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0002\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u001b\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\n\u0008\u0002\u0010\u0004\u001a\u0004\u0018\u00010\u0005\u00a2\u0006\u0004\u0008\u0006\u0010\u0007J\t\u0010\u000c\u001a\u00020\u0003H\u00c6\u0003J\u000b\u0010\r\u001a\u0004\u0018\u00010\u0005H\u00c6\u0003J\u001f\u0010\u000e\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\n\u0008\u0002\u0010\u0004\u001a\u0004\u0018\u00010\u0005H\u00c6\u0001J\u0013\u0010\u000f\u001a\u00020\u00102\u0008\u0010\u0011\u001a\u0004\u0018\u00010\u0012H\u00d6\u0003J\t\u0010\u0013\u001a\u00020\u0014H\u00d6\u0001J\t\u0010\u0015\u001a\u00020\u0005H\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0008\u0010\tR\u0016\u0010\u0004\u001a\u0004\u0018\u00010\u0005X\u0096\u0004\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\n\u0010\u000b\u00a8\u0006\u0016"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;",
        "Ltechnology/cariad/cat/genx/GenXError;",
        "reachability",
        "Ltechnology/cariad/cat/genx/Reachability;",
        "message",
        "",
        "<init>",
        "(Ltechnology/cariad/cat/genx/Reachability;Ljava/lang/String;)V",
        "getReachability",
        "()Ltechnology/cariad/cat/genx/Reachability;",
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
        "",
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

.field private final reachability:Ltechnology/cariad/cat/genx/Reachability;


# direct methods
.method public constructor <init>(Ltechnology/cariad/cat/genx/Reachability;Ljava/lang/String;)V
    .locals 1

    const-string v0, "reachability"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const/4 v0, 0x0

    .line 1
    invoke-direct {p0, v0}, Ltechnology/cariad/cat/genx/GenXError;-><init>(Lkotlin/jvm/internal/g;)V

    iput-object p1, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->reachability:Ltechnology/cariad/cat/genx/Reachability;

    iput-object p2, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->message:Ljava/lang/String;

    return-void
.end method

.method public synthetic constructor <init>(Ltechnology/cariad/cat/genx/Reachability;Ljava/lang/String;ILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    const/4 p2, 0x0

    .line 2
    :cond_0
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;-><init>(Ltechnology/cariad/cat/genx/Reachability;Ljava/lang/String;)V

    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;Ltechnology/cariad/cat/genx/Reachability;Ljava/lang/String;ILjava/lang/Object;)Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;
    .locals 0

    .line 1
    and-int/lit8 p4, p3, 0x1

    .line 2
    .line 3
    if-eqz p4, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->reachability:Ltechnology/cariad/cat/genx/Reachability;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p3, p3, 0x2

    .line 8
    .line 9
    if-eqz p3, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->message:Ljava/lang/String;

    .line 12
    .line 13
    :cond_1
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->copy(Ltechnology/cariad/cat/genx/Reachability;Ljava/lang/String;)Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;

    .line 14
    .line 15
    .line 16
    move-result-object p0

    .line 17
    return-object p0
.end method


# virtual methods
.method public final component1()Ltechnology/cariad/cat/genx/Reachability;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->reachability:Ltechnology/cariad/cat/genx/Reachability;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->message:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ltechnology/cariad/cat/genx/Reachability;Ljava/lang/String;)Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;
    .locals 0

    .line 1
    const-string p0, "reachability"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    new-instance p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;

    .line 7
    .line 8
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;-><init>(Ltechnology/cariad/cat/genx/Reachability;Ljava/lang/String;)V

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
    instance-of v1, p1, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;

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
    check-cast p1, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;

    .line 12
    .line 13
    iget-object v1, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->reachability:Ltechnology/cariad/cat/genx/Reachability;

    .line 14
    .line 15
    iget-object v3, p1, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->reachability:Ltechnology/cariad/cat/genx/Reachability;

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->message:Ljava/lang/String;

    .line 21
    .line 22
    iget-object p1, p1, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->message:Ljava/lang/String;

    .line 23
    .line 24
    invoke-static {p0, p1}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    if-nez p0, :cond_3

    .line 29
    .line 30
    return v2

    .line 31
    :cond_3
    return v0
.end method

.method public getMessage()Ljava/lang/String;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->message:Ljava/lang/String;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getReachability()Ltechnology/cariad/cat/genx/Reachability;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->reachability:Ltechnology/cariad/cat/genx/Reachability;

    .line 2
    .line 3
    return-object p0
.end method

.method public hashCode()I
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->reachability:Ltechnology/cariad/cat/genx/Reachability;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->hashCode()I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    mul-int/lit8 v0, v0, 0x1f

    .line 8
    .line 9
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->message:Ljava/lang/String;

    .line 10
    .line 11
    if-nez p0, :cond_0

    .line 12
    .line 13
    const/4 p0, 0x0

    .line 14
    goto :goto_0

    .line 15
    :cond_0
    invoke-virtual {p0}, Ljava/lang/String;->hashCode()I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    :goto_0
    add-int/2addr v0, p0

    .line 20
    return v0
.end method

.method public toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->reachability:Ltechnology/cariad/cat/genx/Reachability;

    .line 2
    .line 3
    iget-object p0, p0, Ltechnology/cariad/cat/genx/GenXError$ConnectNotAllowed;->message:Ljava/lang/String;

    .line 4
    .line 5
    new-instance v1, Ljava/lang/StringBuilder;

    .line 6
    .line 7
    const-string v2, "ConnectNotAllowed(reachability="

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
