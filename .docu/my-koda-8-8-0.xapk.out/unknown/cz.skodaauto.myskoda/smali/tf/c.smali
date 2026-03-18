.class public final Ltf/c;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Ljava/lang/String;

.field public final e:Ljd/b;

.field public final f:Lyj/b;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/c2;


# direct methods
.method public constructor <init>(Ljava/lang/String;Ljd/b;Lyj/b;)V
    .locals 1

    .line 1
    const-string v0, "vin"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Ltf/c;->d:Ljava/lang/String;

    .line 10
    .line 11
    iput-object p2, p0, Ltf/c;->e:Ljd/b;

    .line 12
    .line 13
    iput-object p3, p0, Ltf/c;->f:Lyj/b;

    .line 14
    .line 15
    new-instance p1, Llc/q;

    .line 16
    .line 17
    sget-object p2, Llx0/b0;->a:Llx0/b0;

    .line 18
    .line 19
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 20
    .line 21
    .line 22
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 23
    .line 24
    .line 25
    move-result-object p1

    .line 26
    iput-object p1, p0, Ltf/c;->g:Lyy0/c2;

    .line 27
    .line 28
    iput-object p1, p0, Ltf/c;->h:Lyy0/c2;

    .line 29
    .line 30
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 31
    .line 32
    .line 33
    move-result-object p1

    .line 34
    new-instance p2, Ltf/b;

    .line 35
    .line 36
    const/4 p3, 0x0

    .line 37
    const/4 v0, 0x0

    .line 38
    invoke-direct {p2, p0, v0, p3}, Ltf/b;-><init>(Ltf/c;Lkotlin/coroutines/Continuation;I)V

    .line 39
    .line 40
    .line 41
    const/4 p0, 0x3

    .line 42
    invoke-static {p1, v0, v0, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 43
    .line 44
    .line 45
    return-void
.end method
