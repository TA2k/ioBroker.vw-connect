.class public final Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithRetry;
.super Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedSubState;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x19
    name = "ConnectionFailedWithRetry"
.end annotation

.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000\u0010\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0008\u0008\u0000\u0018\u00002\u00020\u0001B\u000f\u0012\u0006\u0010\u0003\u001a\u00020\u0002\u00a2\u0006\u0004\u0008\u0004\u0010\u0005R\"\u0010\u0003\u001a\u00020\u00028\u0016@\u0016X\u0096\u000e\u00a2\u0006\u0012\n\u0004\u0008\u0003\u0010\u0006\u001a\u0004\u0008\u0007\u0010\u0008\"\u0004\u0008\t\u0010\u0005\u00a8\u0006\n"
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithRetry;",
        "Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedSubState;",
        "Lt71/c;",
        "connectionErrorStatus",
        "<init>",
        "(Lt71/c;)V",
        "Lt71/c;",
        "getConnectionErrorStatus",
        "()Lt71/c;",
        "setConnectionErrorStatus",
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
.field private connectionErrorStatus:Lt71/c;


# direct methods
.method public constructor <init>(Lt71/c;)V
    .locals 1

    .line 1
    const-string v0, "connectionErrorStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedSubState;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithRetry;->connectionErrorStatus:Lt71/c;

    .line 10
    .line 11
    return-void
.end method


# virtual methods
.method public getConnectionErrorStatus()Lt71/c;
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithRetry;->connectionErrorStatus:Lt71/c;

    .line 2
    .line 3
    return-object p0
.end method

.method public setConnectionErrorStatus(Lt71/c;)V
    .locals 1

    .line 1
    const-string v0, "<set-?>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassistcoremeb/rpa/state/ConnectionFailedState$ConnectionFailedWithRetry;->connectionErrorStatus:Lt71/c;

    .line 7
    .line 8
    return-void
.end method
