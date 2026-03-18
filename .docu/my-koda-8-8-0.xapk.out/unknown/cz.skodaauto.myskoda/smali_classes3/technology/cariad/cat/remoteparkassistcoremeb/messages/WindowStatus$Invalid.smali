.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Invalid"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000&\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0006\n\u0002\u0010\u000b\n\u0000\n\u0002\u0010\u0000\n\u0002\u0008\u0002\n\u0002\u0010\u000e\n\u0000\u0008\u0086\u0008\u0018\u00002\u00020\u0001B\u0011\u0008\u0000\u0012\u0006\u0010\u0002\u001a\u00020\u0003\u00a2\u0006\u0004\u0008\u0004\u0010\u0005J\t\u0010\u0006\u001a\u00020\u0003H\u00c2\u0003J\u0018\u0010\u0007\u001a\u00020\u00002\u0008\u0008\u0002\u0010\u0002\u001a\u00020\u0003H\u00c0\u0001\u00a2\u0006\u0002\u0008\u0008J\u0013\u0010\t\u001a\u00020\n2\u0008\u0010\u000b\u001a\u0004\u0018\u00010\u000cH\u00d6\u0003J\t\u0010\r\u001a\u00020\u0003H\u00d6\u0001J\t\u0010\u000e\u001a\u00020\u000fH\u00d6\u0001R\u000e\u0010\u0002\u001a\u00020\u0003X\u0082\u0004\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u0010"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;",
        "payloadValue",
        "",
        "<init>",
        "(I)V",
        "component1",
        "copy",
        "copy$remoteparkassistcoremeb_release",
        "equals",
        "",
        "other",
        "",
        "hashCode",
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
.field private final payloadValue:I


# direct methods
.method public constructor <init>(I)V
    .locals 1

    .line 1
    const/4 v0, 0x0

    .line 2
    invoke-direct {p0, p1, v0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;-><init>(ILkotlin/jvm/internal/g;)V

    .line 3
    .line 4
    .line 5
    iput p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;->payloadValue:I

    .line 6
    .line 7
    return-void
.end method

.method private final component1()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;->payloadValue:I

    .line 2
    .line 3
    return p0
.end method

.method public static synthetic copy$remoteparkassistcoremeb_release$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;IILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;
    .locals 0

    .line 1
    and-int/lit8 p2, p2, 0x1

    .line 2
    .line 3
    if-eqz p2, :cond_0

    .line 4
    .line 5
    iget p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;->payloadValue:I

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;->copy$remoteparkassistcoremeb_release(I)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public final copy$remoteparkassistcoremeb_release(I)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;
    .locals 0

    .line 1
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;

    .line 2
    .line 3
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-object p0
.end method

.method public equals(Ljava/lang/Object;)Z
    .locals 3

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;

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
    check-cast p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;

    .line 12
    .line 13
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;->payloadValue:I

    .line 14
    .line 15
    iget p1, p1, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;->payloadValue:I

    .line 16
    .line 17
    if-eq p0, p1, :cond_2

    .line 18
    .line 19
    return v2

    .line 20
    :cond_2
    return v0
.end method

.method public hashCode()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;->payloadValue:I

    .line 2
    .line 3
    invoke-static {p0}, Ljava/lang/Integer;->hashCode(I)I

    .line 4
    .line 5
    .line 6
    move-result p0

    .line 7
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;->payloadValue:I

    .line 2
    .line 3
    const-string v0, "Invalid(payloadValue="

    .line 4
    .line 5
    const-string v1, ")"

    .line 6
    .line 7
    invoke-static {v0, p0, v1}, Lu/w;->e(Ljava/lang/String;ILjava/lang/String;)Ljava/lang/String;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method
