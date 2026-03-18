.class public final Lhe/i;
.super Landroidx/lifecycle/b1;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final d:Lei/a;

.field public final e:Lxh/e;

.field public final f:Lhe/d;

.field public final g:Lyy0/c2;

.field public final h:Lyy0/c2;


# direct methods
.method public constructor <init>(Lei/a;Lxh/e;)V
    .locals 2

    .line 1
    invoke-direct {p0}, Landroidx/lifecycle/b1;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lhe/i;->d:Lei/a;

    .line 5
    .line 6
    iput-object p2, p0, Lhe/i;->e:Lxh/e;

    .line 7
    .line 8
    sget-object p1, Lhe/d;->a:Lhe/d;

    .line 9
    .line 10
    iput-object p1, p0, Lhe/i;->f:Lhe/d;

    .line 11
    .line 12
    new-instance p1, Llc/q;

    .line 13
    .line 14
    sget-object p2, Llc/a;->c:Llc/c;

    .line 15
    .line 16
    invoke-direct {p1, p2}, Llc/q;-><init>(Ljava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    invoke-static {p1}, Lyy0/u;->c(Ljava/lang/Object;)Lyy0/c2;

    .line 20
    .line 21
    .line 22
    move-result-object p1

    .line 23
    iput-object p1, p0, Lhe/i;->g:Lyy0/c2;

    .line 24
    .line 25
    iput-object p1, p0, Lhe/i;->h:Lyy0/c2;

    .line 26
    .line 27
    invoke-static {p0}, Landroidx/lifecycle/v0;->i(Landroidx/lifecycle/b1;)Lr7/a;

    .line 28
    .line 29
    .line 30
    move-result-object p1

    .line 31
    new-instance p2, Lh40/h;

    .line 32
    .line 33
    const/16 v0, 0xc

    .line 34
    .line 35
    const/4 v1, 0x0

    .line 36
    invoke-direct {p2, p0, v1, v0}, Lh40/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 37
    .line 38
    .line 39
    const/4 p0, 0x3

    .line 40
    invoke-static {p1, v1, v1, p2, p0}, Lvy0/e0;->E(Lvy0/b0;Lpx0/g;Lvy0/c0;Lay0/n;I)Lvy0/x1;

    .line 41
    .line 42
    .line 43
    return-void
.end method
