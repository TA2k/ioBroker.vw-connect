.class public final Lx60/j;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lwr0/i;

.field public final i:Lwr0/l;

.field public final j:Lij0/a;


# direct methods
.method public constructor <init>(Lwr0/i;Lwr0/l;Lij0/a;)V
    .locals 4

    .line 1
    new-instance v0, Lx60/i;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v3, v2}, Lx60/i;-><init>(Ljava/lang/String;Ljava/lang/String;Z)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lx60/j;->h:Lwr0/i;

    .line 14
    .line 15
    iput-object p2, p0, Lx60/j;->i:Lwr0/l;

    .line 16
    .line 17
    iput-object p3, p0, Lx60/j;->j:Lij0/a;

    .line 18
    .line 19
    new-instance p1, Lvo0/e;

    .line 20
    .line 21
    const/16 p2, 0x16

    .line 22
    .line 23
    invoke-direct {p1, p0, v3, p2}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method
