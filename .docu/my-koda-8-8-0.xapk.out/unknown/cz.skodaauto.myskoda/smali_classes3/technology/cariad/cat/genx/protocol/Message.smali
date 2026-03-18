.class public final Ltechnology/cariad/cat/genx/protocol/Message;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/MemberClasses;
    value = {
        Ltechnology/cariad/cat/genx/protocol/Message$Companion;
    }
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000>\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0012\n\u0002\u0008\u0002\n\u0002\u0010\t\n\u0002\u0010\u0005\n\u0002\u0008\u000c\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u000e\n\u0002\u0008\u0007\u0008\u0086\u0008\u0018\u0000 \"2\u00020\u0001:\u0001\"B\'\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u0012\u0006\u0010\u0004\u001a\u00020\u0005\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u0012\u0006\u0010\u0008\u001a\u00020\t\u00a2\u0006\u0004\u0008\n\u0010\u000bB)\u0008\u0017\u0012\u0006\u0010\u0002\u001a\u00020\u000c\u0012\u0006\u0010\u0004\u001a\u00020\r\u0012\u0006\u0010\u0006\u001a\u00020\u0007\u0012\u0006\u0010\u0008\u001a\u00020\t\u00a2\u0006\u0004\u0008\n\u0010\u000eJ\u0013\u0010\u0017\u001a\u00020\u00072\u0008\u0010\u0018\u001a\u0004\u0018\u00010\u0001H\u0096\u0002J\u0008\u0010\u0019\u001a\u00020\u001aH\u0016J\u0008\u0010\u001b\u001a\u00020\u001cH\u0016J\t\u0010\u001d\u001a\u00020\u0003H\u00c6\u0003J\t\u0010\u001e\u001a\u00020\u0005H\u00c6\u0003J\t\u0010\u001f\u001a\u00020\u0007H\u00c6\u0003J\t\u0010 \u001a\u00020\tH\u00c6\u0003J1\u0010!\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u00032\u0008\u0008\u0002\u0010\u0004\u001a\u00020\u00052\u0008\u0008\u0002\u0010\u0006\u001a\u00020\u00072\u0008\u0008\u0002\u0010\u0008\u001a\u00020\tH\u00c6\u0001R\u0011\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u000f\u0010\u0010R\u0011\u0010\u0004\u001a\u00020\u0005\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0011\u0010\u0012R\u0011\u0010\u0006\u001a\u00020\u0007\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0013\u0010\u0014R\u0011\u0010\u0008\u001a\u00020\t\u00a2\u0006\u0008\n\u0000\u001a\u0004\u0008\u0015\u0010\u0016\u00a8\u0006#"
    }
    d2 = {
        "Ltechnology/cariad/cat/genx/protocol/Message;",
        "",
        "address",
        "Ltechnology/cariad/cat/genx/protocol/Address;",
        "priority",
        "Ltechnology/cariad/cat/genx/protocol/Priority;",
        "requiresQueuing",
        "",
        "data",
        "",
        "<init>",
        "(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)V",
        "",
        "",
        "(JBZ[B)V",
        "getAddress",
        "()Ltechnology/cariad/cat/genx/protocol/Address;",
        "getPriority",
        "()Ltechnology/cariad/cat/genx/protocol/Priority;",
        "getRequiresQueuing",
        "()Z",
        "getData",
        "()[B",
        "equals",
        "other",
        "hashCode",
        "",
        "toString",
        "",
        "component1",
        "component2",
        "component3",
        "component4",
        "copy",
        "Companion",
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


# static fields
.field public static final Companion:Ltechnology/cariad/cat/genx/protocol/Message$Companion;


# instance fields
.field private final address:Ltechnology/cariad/cat/genx/protocol/Address;

.field private final data:[B

.field private final priority:Ltechnology/cariad/cat/genx/protocol/Priority;

.field private final requiresQueuing:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/Message$Companion;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Ltechnology/cariad/cat/genx/protocol/Message$Companion;-><init>(Lkotlin/jvm/internal/g;)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ltechnology/cariad/cat/genx/protocol/Message;->Companion:Ltechnology/cariad/cat/genx/protocol/Message$Companion;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(JBZ[B)V
    .locals 1
    .annotation runtime Llx0/c;
    .end annotation

    const-string v0, "data"

    invoke-static {p5, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 2
    new-instance v0, Ltechnology/cariad/cat/genx/protocol/Address;

    invoke-direct {v0, p1, p2}, Ltechnology/cariad/cat/genx/protocol/Address;-><init>(J)V

    .line 3
    invoke-static {p3}, Ltechnology/cariad/cat/genx/protocol/PriorityKt;->toPriority(B)Ltechnology/cariad/cat/genx/protocol/Priority;

    move-result-object p1

    .line 4
    invoke-direct {p0, v0, p1, p4, p5}, Ltechnology/cariad/cat/genx/protocol/Message;-><init>(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)V

    return-void
.end method

.method public constructor <init>(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)V
    .locals 1

    const-string v0, "address"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "priority"

    invoke-static {p2, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    const-string v0, "data"

    invoke-static {p4, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput-object p1, p0, Ltechnology/cariad/cat/genx/protocol/Message;->address:Ltechnology/cariad/cat/genx/protocol/Address;

    iput-object p2, p0, Ltechnology/cariad/cat/genx/protocol/Message;->priority:Ltechnology/cariad/cat/genx/protocol/Priority;

    iput-boolean p3, p0, Ltechnology/cariad/cat/genx/protocol/Message;->requiresQueuing:Z

    iput-object p4, p0, Ltechnology/cariad/cat/genx/protocol/Message;->data:[B

    return-void
.end method

.method public static synthetic copy$default(Ltechnology/cariad/cat/genx/protocol/Message;Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[BILjava/lang/Object;)Ltechnology/cariad/cat/genx/protocol/Message;
    .locals 0

    .line 1
    and-int/lit8 p6, p5, 0x1

    .line 2
    .line 3
    if-eqz p6, :cond_0

    .line 4
    .line 5
    iget-object p1, p0, Ltechnology/cariad/cat/genx/protocol/Message;->address:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 6
    .line 7
    :cond_0
    and-int/lit8 p6, p5, 0x2

    .line 8
    .line 9
    if-eqz p6, :cond_1

    .line 10
    .line 11
    iget-object p2, p0, Ltechnology/cariad/cat/genx/protocol/Message;->priority:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 12
    .line 13
    :cond_1
    and-int/lit8 p6, p5, 0x4

    .line 14
    .line 15
    if-eqz p6, :cond_2

    .line 16
    .line 17
    iget-boolean p3, p0, Ltechnology/cariad/cat/genx/protocol/Message;->requiresQueuing:Z

    .line 18
    .line 19
    :cond_2
    and-int/lit8 p5, p5, 0x8

    .line 20
    .line 21
    if-eqz p5, :cond_3

    .line 22
    .line 23
    iget-object p4, p0, Ltechnology/cariad/cat/genx/protocol/Message;->data:[B

    .line 24
    .line 25
    :cond_3
    invoke-virtual {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/protocol/Message;->copy(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)Ltechnology/cariad/cat/genx/protocol/Message;

    .line 26
    .line 27
    .line 28
    move-result-object p0

    .line 29
    return-object p0
.end method


# virtual methods
.method public final component1()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->address:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component2()Ltechnology/cariad/cat/genx/protocol/Priority;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->priority:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 2
    .line 3
    return-object p0
.end method

.method public final component3()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->requiresQueuing:Z

    .line 2
    .line 3
    return p0
.end method

.method public final component4()[B
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->data:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public final copy(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)Ltechnology/cariad/cat/genx/protocol/Message;
    .locals 0

    .line 1
    const-string p0, "address"

    .line 2
    .line 3
    invoke-static {p1, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    const-string p0, "priority"

    .line 7
    .line 8
    invoke-static {p2, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    const-string p0, "data"

    .line 12
    .line 13
    invoke-static {p4, p0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    new-instance p0, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 17
    .line 18
    invoke-direct {p0, p1, p2, p3, p4}, Ltechnology/cariad/cat/genx/protocol/Message;-><init>(Ltechnology/cariad/cat/genx/protocol/Address;Ltechnology/cariad/cat/genx/protocol/Priority;Z[B)V

    .line 19
    .line 20
    .line 21
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
    if-eqz p1, :cond_1

    .line 6
    .line 7
    invoke-virtual {p1}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 8
    .line 9
    .line 10
    move-result-object v1

    .line 11
    goto :goto_0

    .line 12
    :cond_1
    const/4 v1, 0x0

    .line 13
    :goto_0
    const-class v2, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 14
    .line 15
    invoke-virtual {v2, v1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 16
    .line 17
    .line 18
    move-result v1

    .line 19
    const/4 v2, 0x0

    .line 20
    if-nez v1, :cond_2

    .line 21
    .line 22
    return v2

    .line 23
    :cond_2
    const-string v1, "null cannot be cast to non-null type technology.cariad.cat.genx.protocol.Message"

    .line 24
    .line 25
    invoke-static {p1, v1}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    check-cast p1, Ltechnology/cariad/cat/genx/protocol/Message;

    .line 29
    .line 30
    iget-object v1, p0, Ltechnology/cariad/cat/genx/protocol/Message;->address:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 31
    .line 32
    iget-object v3, p1, Ltechnology/cariad/cat/genx/protocol/Message;->address:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 33
    .line 34
    invoke-static {v1, v3}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 35
    .line 36
    .line 37
    move-result v1

    .line 38
    if-nez v1, :cond_3

    .line 39
    .line 40
    return v2

    .line 41
    :cond_3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/protocol/Message;->priority:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 42
    .line 43
    iget-object v3, p1, Ltechnology/cariad/cat/genx/protocol/Message;->priority:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 44
    .line 45
    if-eq v1, v3, :cond_4

    .line 46
    .line 47
    return v2

    .line 48
    :cond_4
    iget-boolean v1, p0, Ltechnology/cariad/cat/genx/protocol/Message;->requiresQueuing:Z

    .line 49
    .line 50
    iget-boolean v3, p1, Ltechnology/cariad/cat/genx/protocol/Message;->requiresQueuing:Z

    .line 51
    .line 52
    if-eq v1, v3, :cond_5

    .line 53
    .line 54
    return v2

    .line 55
    :cond_5
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->data:[B

    .line 56
    .line 57
    iget-object p1, p1, Ltechnology/cariad/cat/genx/protocol/Message;->data:[B

    .line 58
    .line 59
    invoke-static {p0, p1}, Ljava/util/Arrays;->equals([B[B)Z

    .line 60
    .line 61
    .line 62
    move-result p0

    .line 63
    if-nez p0, :cond_6

    .line 64
    .line 65
    return v2

    .line 66
    :cond_6
    return v0
.end method

.method public final getAddress()Ltechnology/cariad/cat/genx/protocol/Address;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->address:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getData()[B
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->data:[B

    .line 2
    .line 3
    return-object p0
.end method

.method public final getPriority()Ltechnology/cariad/cat/genx/protocol/Priority;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->priority:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 2
    .line 3
    return-object p0
.end method

.method public final getRequiresQueuing()Z
    .locals 0

    .line 1
    iget-boolean p0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->requiresQueuing:Z

    .line 2
    .line 3
    return p0
.end method

.method public hashCode()I
    .locals 3

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->address:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    invoke-virtual {v0}, Ltechnology/cariad/cat/genx/protocol/Address;->hashCode()I

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
    iget-object v2, p0, Ltechnology/cariad/cat/genx/protocol/Message;->priority:Ltechnology/cariad/cat/genx/protocol/Priority;

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
    iget-boolean v0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->requiresQueuing:Z

    .line 19
    .line 20
    invoke-static {v2, v1, v0}, La7/g0;->e(IIZ)I

    .line 21
    .line 22
    .line 23
    move-result v0

    .line 24
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->data:[B

    .line 25
    .line 26
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([B)I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    add-int/2addr p0, v0

    .line 31
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 5

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->address:Ltechnology/cariad/cat/genx/protocol/Address;

    .line 2
    .line 3
    iget-object v1, p0, Ltechnology/cariad/cat/genx/protocol/Message;->priority:Ltechnology/cariad/cat/genx/protocol/Priority;

    .line 4
    .line 5
    iget-boolean v2, p0, Ltechnology/cariad/cat/genx/protocol/Message;->requiresQueuing:Z

    .line 6
    .line 7
    iget-object p0, p0, Ltechnology/cariad/cat/genx/protocol/Message;->data:[B

    .line 8
    .line 9
    invoke-static {p0}, Lly0/d;->l([B)Ljava/lang/String;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    new-instance v3, Ljava/lang/StringBuilder;

    .line 14
    .line 15
    const-string v4, "Message(address="

    .line 16
    .line 17
    invoke-direct {v3, v4}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 18
    .line 19
    .line 20
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 21
    .line 22
    .line 23
    const-string v0, ", priority="

    .line 24
    .line 25
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 26
    .line 27
    .line 28
    invoke-virtual {v3, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 29
    .line 30
    .line 31
    const-string v0, ", requiresQueuing="

    .line 32
    .line 33
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 34
    .line 35
    .line 36
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 37
    .line 38
    .line 39
    const-string v0, ", data="

    .line 40
    .line 41
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 42
    .line 43
    .line 44
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string p0, ")"

    .line 48
    .line 49
    invoke-virtual {v3, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 53
    .line 54
    .line 55
    move-result-object p0

    .line 56
    return-object p0
.end method
