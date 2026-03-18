.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Companion;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "Companion"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\"\n\u0002\u0018\u0002\n\u0002\u0010\u0000\n\u0002\u0008\u0003\n\u0002\u0010\u0008\n\u0000\n\u0002\u0010\u0007\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0002\u0008\u0086\u0003\u0018\u00002\u00020\u0001B\t\u0008\u0002\u00a2\u0006\u0004\u0008\u0002\u0010\u0003J\u0014\u0010\t\u001a\u00020\n*\u00020\u00052\u0008\u0008\u0002\u0010\u000b\u001a\u00020\u0005R\u000e\u0010\u0004\u001a\u00020\u0005X\u0082T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0006\u001a\u00020\u0007X\u0082T\u00a2\u0006\u0002\n\u0000R\u000e\u0010\u0008\u001a\u00020\u0007X\u0082T\u00a2\u0006\u0002\n\u0000\u00a8\u0006\u000c"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Companion;",
        "",
        "<init>",
        "()V",
        "WINDOW_STATE_COMPLETELY_OPEN_VALUE",
        "",
        "WINDOW_STATE_OPEN_PERCENTAGE",
        "",
        "WINDOW_STATE_CLOSED_PERCENTAGE",
        "toWindowStatus",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;",
        "completelyOpenValue",
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


# direct methods
.method private constructor <init>()V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

.method public synthetic constructor <init>(Lkotlin/jvm/internal/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Companion;-><init>()V

    return-void
.end method

.method public static synthetic toWindowStatus$default(Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Companion;IIILjava/lang/Object;)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 0

    .line 1
    and-int/lit8 p3, p3, 0x1

    .line 2
    .line 3
    if-eqz p3, :cond_0

    .line 4
    .line 5
    const/16 p2, 0xc8

    .line 6
    .line 7
    :cond_0
    invoke-virtual {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Companion;->toWindowStatus(II)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;

    .line 8
    .line 9
    .line 10
    move-result-object p0

    .line 11
    return-object p0
.end method


# virtual methods
.method public final toWindowStatus(II)Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus;
    .locals 1

    .line 1
    int-to-float p0, p1

    .line 2
    int-to-float p2, p2

    .line 3
    div-float/2addr p0, p2

    .line 4
    const/4 p2, 0x0

    .line 5
    cmpg-float p2, p0, p2

    .line 6
    .line 7
    if-ltz p2, :cond_2

    .line 8
    .line 9
    const/high16 v0, 0x3f800000    # 1.0f

    .line 10
    .line 11
    cmpl-float v0, p0, v0

    .line 12
    .line 13
    if-lez v0, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    if-nez p2, :cond_1

    .line 17
    .line 18
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;

    .line 19
    .line 20
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Closed;-><init>(I)V

    .line 21
    .line 22
    .line 23
    return-object p0

    .line 24
    :cond_1
    new-instance p2, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;

    .line 25
    .line 26
    invoke-direct {p2, p1, p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Open;-><init>(IF)V

    .line 27
    .line 28
    .line 29
    return-object p2

    .line 30
    :cond_2
    :goto_0
    new-instance p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;

    .line 31
    .line 32
    invoke-direct {p0, p1}, Ltechnology/cariad/cat/remoteparkassistcoremeb/messages/WindowStatus$Invalid;-><init>(I)V

    .line 33
    .line 34
    .line 35
    return-object p0
.end method
