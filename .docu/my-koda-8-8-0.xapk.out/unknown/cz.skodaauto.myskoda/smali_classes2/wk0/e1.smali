.class public final Lwk0/e1;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Luk0/b0;

.field public final i:Lnn0/v;

.field public final j:Lkf0/k;


# direct methods
.method public constructor <init>(Luk0/b0;Lnn0/v;Lkf0/k;)V
    .locals 1

    .line 1
    new-instance v0, Lwk0/d1;

    .line 2
    .line 3
    invoke-direct {v0}, Lwk0/d1;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lwk0/e1;->h:Luk0/b0;

    .line 10
    .line 11
    iput-object p2, p0, Lwk0/e1;->i:Lnn0/v;

    .line 12
    .line 13
    iput-object p3, p0, Lwk0/e1;->j:Lkf0/k;

    .line 14
    .line 15
    new-instance p1, Lvo0/e;

    .line 16
    .line 17
    const/4 p2, 0x0

    .line 18
    const/16 p3, 0xf

    .line 19
    .line 20
    invoke-direct {p1, p0, p2, p3}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 21
    .line 22
    .line 23
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 24
    .line 25
    .line 26
    return-void
.end method
