.class public final Ly20/p;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lw20/c;


# direct methods
.method public constructor <init>(Lgb0/a0;Lw20/c;)V
    .locals 3

    .line 1
    new-instance v0, Ly20/o;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    invoke-direct {v0, v1, v2}, Ly20/o;-><init>(Ljava/lang/String;Lhp0/e;)V

    .line 7
    .line 8
    .line 9
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 10
    .line 11
    .line 12
    iput-object p2, p0, Ly20/p;->h:Lw20/c;

    .line 13
    .line 14
    new-instance p2, Lwp0/c;

    .line 15
    .line 16
    const/16 v0, 0xc

    .line 17
    .line 18
    invoke-direct {p2, v0, p1, p0, v2}, Lwp0/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 19
    .line 20
    .line 21
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 22
    .line 23
    .line 24
    return-void
.end method
