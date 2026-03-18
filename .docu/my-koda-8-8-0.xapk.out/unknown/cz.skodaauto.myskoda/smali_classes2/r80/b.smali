.class public final Lr80/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lcr0/j;

.field public final i:Lij0/a;

.field public final j:Lq80/m;

.field public final k:Lkf0/k;


# direct methods
.method public constructor <init>(Lcr0/j;Lij0/a;Lq80/m;Lkf0/k;)V
    .locals 2

    .line 1
    new-instance v0, Lr80/a;

    .line 2
    .line 3
    const/4 v1, 0x0

    .line 4
    invoke-direct {v0, v1}, Lr80/a;-><init>(Ljava/lang/String;)V

    .line 5
    .line 6
    .line 7
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 8
    .line 9
    .line 10
    iput-object p1, p0, Lr80/b;->h:Lcr0/j;

    .line 11
    .line 12
    iput-object p2, p0, Lr80/b;->i:Lij0/a;

    .line 13
    .line 14
    iput-object p3, p0, Lr80/b;->j:Lq80/m;

    .line 15
    .line 16
    iput-object p4, p0, Lr80/b;->k:Lkf0/k;

    .line 17
    .line 18
    new-instance p1, Ln00/f;

    .line 19
    .line 20
    const/16 p2, 0x1a

    .line 21
    .line 22
    invoke-direct {p1, p0, v1, p2}, Ln00/f;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method
