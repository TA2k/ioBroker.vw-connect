.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u001e\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0010\u000b\n\u0002\u0008\u0012\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B/\u0012\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u0003\u0012\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0007\u0010\u0008J\t\u0010\u000e\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u000f\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0010\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u0011\u001a\u00020\u0003H\u00c6\u0003J1\u0010\u0012\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0005\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u0003H\u00c6\u0001J\u0013\u0010\u0013\u001a\u00020\u00032\u0008\u0010\u0014\u001a\u0004\u0018\u00010\u0001H\u00d6\u0003J\t\u0010\u0015\u001a\u00020\u0016H\u00d6\u0001J\t\u0010\u0017\u001a\u00020\u0018H\u00d6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\t\u0010\nR\u0011\u0010\u0004\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000b\u0010\nR\u0011\u0010\u0005\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000c\u0010\nR\u0011\u0010\u0006\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\r\u0010\n\u00a8\u0006\u0019"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;",
        "",
        "standStill",
        "",
        "request_P_EPB",
        "vmm_P",
        "vmm_EPB",
        "<init>",
        "(ZZZZ)V",
        "getStandStill",
        "()Z",
        "getRequest_P_EPB",
        "getVmm_P",
        "getVmm_EPB",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
        "equals",
        "other",
        "hashCode",
        "",
        "toString",
        "",
        "remoteparkassistcoremeb_release"
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
.field private final request_P_EPB:Z

.field private final standStill:Z

.field private final vmm_EPB:Z

.field private final vmm_P:Z


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

    invoke-direct/range {v0 .. v6}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;-><init>(ZZZZILkotlin/jvm/internal/g;)V

    return-void
.end method

.method public constructor <init>(ZZZZ)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->standStill:Z

    .line 4
    iput-boolean p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->request_P_EPB:Z

    .line 5
    iput-boolean p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_P:Z

    .line 6
    iput-boolean p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_EPB:Z

    return-void
.end method

.method public synthetic constructor <init>(ZZZZILkotlin/jvm/internal/g;)V
    .locals 1

    and-int/lit8 p6, p5, 0x1

    const/4 v0, 0x0

    if-eqz p6, :cond_0

    move p1, v0

    :cond_0
    and-int/lit8 p6, p5, 0x2

    if-eqz p6, :cond_1

    move p2, v0

    :cond_1
    and-int/lit8 p6, p5, 0x4

    if-eqz p6, :cond_2

    move p3, v0

    :cond_2
    and-int/lit8 p5, p5, 0x8

    if-eqz p5, :cond_3

    move p4, v0

    .line 7
    :cond_3
    invoke-direct {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;-><init>(ZZZZ)V

    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;ZZZZILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-boolean p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->standStill:Z

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-boolean p2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->request_P_EPB:Z

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-boolean p3, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_P:Z

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-boolean p4, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_EPB:Z

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->copy(ZZZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

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
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->standStill:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component2()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->request_P_EPB:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component3()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_P:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component4()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_EPB:Z

    .line 2
    .line 3
    return p0
.end method

.method public final copy(ZZZZ)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;
    .locals 0

    .line 1
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 2
    .line 3
    invoke-direct {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;-><init>(ZZZZ)V

    .line 4
    .line 5
    .line 6
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
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;

    .line 12
    .line 13
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->standStill:Z

    .line 14
    .line 15
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->standStill:Z

    .line 16
    .line 17
    if-eq v1, v3, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->request_P_EPB:Z

    .line 21
    .line 22
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->request_P_EPB:Z

    .line 23
    .line 24
    if-eq v1, v3, :cond_3

    .line 25
    .line 26
    return v2

    .line 27
    :cond_3
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_P:Z

    .line 28
    .line 29
    iget-boolean v3, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_P:Z

    .line 30
    .line 31
    if-eq v1, v3, :cond_4

    .line 32
    .line 33
    return v2

    .line 34
    :cond_4
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_EPB:Z

    .line 35
    .line 36
    iget-boolean p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_EPB:Z

    .line 37
    .line 38
    if-eq p0, p1, :cond_5

    .line 39
    .line 40
    return v2

    .line 41
    :cond_5
    return v0
.end method

.method public final getRequest_P_EPB()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->request_P_EPB:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getStandStill()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->standStill:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getVmm_EPB()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_EPB:Z

    .line 2
    .line 3
    return p0
.end method

.method public final getVmm_P()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_P:Z

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->standStill:Z

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
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->request_P_EPB:Z

    .line 11
    .line 12
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 13
    .line 14
    .line 15
    move-result v0

    .line 16
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_P:Z

    .line 17
    .line 18
    invoke-static {v0, v1, v2}, La7/g0;->e(IIZ)I

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_EPB:Z

    .line 23
    .line 24
    invoke-static {p0}, Ljava/lang/Boolean;->hashCode(Z)I

    .line 25
    .line 26
    .line 27
    move-result p0

    .line 28
    add-int/2addr p0, v0

    .line 29
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-boolean v0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->standStill:Z

    .line 2
    .line 3
    iget-boolean v1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->request_P_EPB:Z

    .line 4
    .line 5
    iget-boolean v2, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_P:Z

    .line 6
    .line 7
    iget-boolean p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/ppe/StandStillStatusPPE;->vmm_EPB:Z

    .line 8
    .line 9
    const-string v3, ", request_P_EPB="

    .line 10
    .line 11
    const-string v4, ", vmm_P="

    .line 12
    .line 13
    const-string v5, "StandStillStatusPPE(standStill="

    .line 14
    .line 15
    invoke-static {v5, v3, v4, v0, v1}, Lvj/b;->o(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZ)Ljava/lang/StringBuilder;

    .line 16
    .line 17
    .line 18
    move-result-object v0

    .line 19
    const-string v1, ", vmm_EPB="

    .line 20
    .line 21
    const-string v3, ")"

    .line 22
    .line 23
    invoke-static {v0, v2, v1, p0, v3}, Lvj/b;->l(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object p0

    .line 27
    return-object p0
.end method
