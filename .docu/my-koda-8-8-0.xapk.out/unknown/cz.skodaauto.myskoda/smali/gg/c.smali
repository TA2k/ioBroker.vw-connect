.class public final Lgg/c;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:La2/c;

.field public final e:Lyy0/c2;

.field public final f:Lyy0/c2;


# direct methods
.method public constructor <init>(La2/c;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lgg/c;->d:La2/c;

    .line 5
    .line 6
    new-instance p1, Llc/q;

    .line 7
    .line 8
    sget-object v0, Llc/a;->c:Llc/c;

    .line 9
    .line 10
    invoke-direct {p1, v0}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 14
    .line 15
    .line 16
    move-result-object p1

    .line 17
    iput-object p1, p0, Lgg/c;->e:Lyy0/c2;

    .line 18
    .line 19
    iput-object p1, p0, Lgg/c;->f:Lyy0/c2;

    .line 20
    .line 21
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 22
    .line 23
    .line 24
    move-result-object p1

    .line 25
    new-instance v0, Lg60/w;

    .line 26
    .line 27
    const/4 v1, 0x4

    .line 28
    const/4 v2, 0x0

    .line 29
    invoke-direct {v0, p0, v2, v1}, Lg60/w;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 30
    .line 31
    .line 32
    const/4 p0, 0x3

    .line 33
    invoke-static {p1, v2, v2, v0, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 34
    .line 35
    .line 36
    return-void
.end method
