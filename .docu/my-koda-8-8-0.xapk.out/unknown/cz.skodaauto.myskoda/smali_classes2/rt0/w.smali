.class public final Lrt0/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ltr0/d;


# instance fields
.field public final a:Lbn0/g;


# direct methods
.method public constructor <init>(Lbn0/g;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lrt0/w;->a:Lbn0/g;

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    new-instance v0, Lbn0/c;

    .line 2
    .line 3
    sget-object v1, Lst0/h;->d:[Lst0/h;

    .line 4
    .line 5
    const-string v1, "wakeup"

    .line 6
    .line 7
    const-string v2, "vehicle-wakeup"

    .line 8
    .line 9
    invoke-direct {v0, v2, v1}, Lbn0/c;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 10
    .line 11
    .line 12
    iget-object p0, p0, Lrt0/w;->a:Lbn0/g;

    .line 13
    .line 14
    invoke-virtual {p0, v0}, Lbn0/g;->a(Lbn0/c;)Lzy0/j;

    .line 15
    .line 16
    .line 17
    move-result-object p0

    .line 18
    new-instance v0, Lal0/j0;

    .line 19
    .line 20
    const/16 v1, 0x9

    .line 21
    .line 22
    invoke-direct {v0, p0, v1}, Lal0/j0;-><init>(Lzy0/j;I)V

    .line 23
    .line 24
    .line 25
    new-instance p0, Lal0/m0;

    .line 26
    .line 27
    const/4 v1, 0x2

    .line 28
    const/16 v2, 0x19

    .line 29
    .line 30
    const/4 v3, 0x0

    .line 31
    invoke-direct {p0, v1, v3, v2}, Lal0/m0;-><init>(ILkotlin/coroutines/Continuation;I)V

    .line 32
    .line 33
    .line 34
    new-instance v1, Lne0/n;

    .line 35
    .line 36
    invoke-direct {v1, p0, v0}, Lne0/n;-><init>(Lay0/n;Lyy0/i;)V

    .line 37
    .line 38
    .line 39
    invoke-static {v1}, Lyy0/u;->p(Lyy0/i;)Lyy0/i;

    .line 40
    .line 41
    .line 42
    move-result-object p0

    .line 43
    return-object p0
.end method
