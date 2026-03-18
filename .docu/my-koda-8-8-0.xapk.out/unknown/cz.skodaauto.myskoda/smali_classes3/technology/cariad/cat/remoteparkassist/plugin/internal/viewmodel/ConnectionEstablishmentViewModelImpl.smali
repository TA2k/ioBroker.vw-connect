.class public final Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lv61/a;
.implements Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ConnectionEstablishmentViewModel;
.implements Lz71/a;


# annotations
.annotation runtime Lkotlin/Metadata;
    d1 = {
        "\u0000F\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0002\u0018\u0002\n\u0000\n\u0002\u0010\u0008\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0003\n\u0002\u0018\u0002\n\u0002\u0008\u0007\n\u0002\u0018\u0002\n\u0002\u0008\u0002\n\u0002\u0018\u0002\n\u0002\u0008\u0004\n\u0002\u0010\u000b\n\u0002\u0008\u0002\u0008\u0001\u0018\u00002\u00020\u00012\u00020\u00022\u00020\u0003B\u0019\u0012\u0006\u0010\u0005\u001a\u00020\u0004\u0012\u0008\u0008\u0002\u0010\u0007\u001a\u00020\u0006\u00a2\u0006\u0004\u0008\u0008\u0010\tJ\u000f\u0010\u000b\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\u000b\u0010\u000cJ\u000f\u0010\r\u001a\u00020\nH\u0016\u00a2\u0006\u0004\u0008\r\u0010\u000cJ\u0017\u0010\u0010\u001a\u00020\n2\u0006\u0010\u000f\u001a\u00020\u000eH\u0016\u00a2\u0006\u0004\u0008\u0010\u0010\u0011R\u0014\u0010\u0005\u001a\u00020\u00048\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0005\u0010\u0012R\u001a\u0010\u0007\u001a\u00020\u00068\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u0007\u0010\u0013\u001a\u0004\u0008\u0014\u0010\u0015R\u001a\u0010\u0017\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00168\u0002X\u0082\u0004\u00a2\u0006\u0006\n\u0004\u0008\u0017\u0010\u0018R \u0010\u001a\u001a\u0008\u0012\u0004\u0012\u00020\u000e0\u00198\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u001a\u0010\u001b\u001a\u0004\u0008\u001c\u0010\u001dR \u0010\u001f\u001a\u0008\u0012\u0004\u0012\u00020\u001e0\u00198\u0016X\u0096\u0004\u00a2\u0006\u000c\n\u0004\u0008\u001f\u0010\u001b\u001a\u0004\u0008\u001f\u0010\u001d\u00a8\u0006 "
    }
    d2 = {
        "Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;",
        "Lv61/a;",
        "Ltechnology/cariad/cat/remoteparkassist/plugin/viewmodel/ConnectionEstablishmentViewModel;",
        "Lz71/a;",
        "Le81/l;",
        "viewModelController",
        "",
        "viewModelControllerHashCode",
        "<init>",
        "(Le81/l;I)V",
        "Llx0/b0;",
        "closeRPAModule",
        "()V",
        "close",
        "Lk71/c;",
        "newStatus",
        "connectionEstablishmentConnectionStatusDidChange",
        "(Lk71/c;)V",
        "Le81/l;",
        "I",
        "getViewModelControllerHashCode",
        "()I",
        "Lyy0/j1;",
        "_connectionStatus",
        "Lyy0/j1;",
        "Lyy0/a2;",
        "connectionStatus",
        "Lyy0/a2;",
        "getConnectionStatus",
        "()Lyy0/a2;",
        "",
        "isClosable",
        "remoteparkassistplugin_release"
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
.field public static final $stable:I = 0x8


# instance fields
.field private final _connectionStatus:Lyy0/j1;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/j1;"
        }
    .end annotation
.end field

.field private final connectionStatus:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final isClosable:Lyy0/a2;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Lyy0/a2;"
        }
    .end annotation
.end field

.field private final viewModelController:Le81/l;

.field private final viewModelControllerHashCode:I


# direct methods
.method public constructor <init>(Le81/l;I)V
    .locals 1

    const-string v0, "viewModelController"

    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;->viewModelController:Le81/l;

    .line 3
    iput p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;->viewModelControllerHashCode:I

    .line 4
    sget-object p2, Lk71/c;->f:Lk71/c;

    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    iput-object p2, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;->_connectionStatus:Lyy0/j1;

    .line 5
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 6
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;->connectionStatus:Lyy0/a2;

    .line 7
    sget-object p2, Ljava/lang/Boolean;->TRUE:Ljava/lang/Boolean;

    invoke-static {p2}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    move-result-object p2

    .line 8
    new-instance v0, Lyy0/l1;

    invoke-direct {v0, p2}, Lyy0/l1;-><init>(Lyy0/j1;)V

    .line 9
    iput-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;->isClosable:Lyy0/a2;

    const/4 p2, 0x1

    .line 10
    invoke-interface {p1, p0, p2}, Le81/l;->addObserver(Lz71/a;Z)V

    .line 11
    invoke-interface {p1}, Lz71/h;->onAppear()V

    return-void
.end method

.method public synthetic constructor <init>(Le81/l;IILkotlin/jvm/internal/g;)V
    .locals 0

    and-int/lit8 p3, p3, 0x2

    if-eqz p3, :cond_0

    .line 12
    invoke-virtual {p1}, Ljava/lang/Object;->hashCode()I

    move-result p2

    .line 13
    :cond_0
    invoke-direct {p0, p1, p2}, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;-><init>(Le81/l;I)V

    return-void
.end method


# virtual methods
.method public close()V
    .locals 1

    .line 1
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;->viewModelController:Le81/l;

    .line 2
    .line 3
    invoke-interface {v0}, Lz71/h;->onDisappear()V

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;->viewModelController:Le81/l;

    .line 7
    .line 8
    invoke-interface {v0, p0}, Le81/l;->removeObserver(Lz71/a;)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.method public closeRPAModule()V
    .locals 0

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;->viewModelController:Le81/l;

    .line 2
    .line 3
    invoke-interface {p0}, Lz71/h;->closeScreen()V

    .line 4
    .line 5
    .line 6
    return-void
.end method

.method public connectionEstablishmentConnectionStatusDidChange(Lk71/c;)V
    .locals 3

    .line 1
    const-string v0, "newStatus"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;->_connectionStatus:Lyy0/j1;

    .line 7
    .line 8
    :cond_0
    move-object v0, p0

    .line 9
    check-cast v0, Lyy0/c2;

    .line 10
    .line 11
    invoke-virtual {v0}, Lyy0/c2;->getValue()Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object v1

    .line 15
    move-object v2, v1

    .line 16
    check-cast v2, Lk71/c;

    .line 17
    .line 18
    invoke-virtual {v0, v1, p1}, Lyy0/c2;->i(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 19
    .line 20
    .line 21
    move-result v0

    .line 22
    if-eqz v0, :cond_0

    .line 23
    .line 24
    return-void
.end method

.method public getConnectionStatus()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;->connectionStatus:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method

.method public getViewModelControllerHashCode()I
    .locals 0

    .line 1
    iget p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;->viewModelControllerHashCode:I

    .line 2
    .line 3
    return p0
.end method

.method public isClosable()Lyy0/a2;
    .locals 0
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "()",
            "Lyy0/a2;"
        }
    .end annotation

    .line 1
    iget-object p0, p0, Ltechnology/cariad/cat/remoteparkassist/plugin/internal/viewmodel/ConnectionEstablishmentViewModelImpl;->isClosable:Lyy0/a2;

    .line 2
    .line 3
    return-object p0
.end method
