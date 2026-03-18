.class public final Lw80/i;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lcr0/k;

.field public final i:Lv80/b;

.field public final j:Lq80/l;

.field public final k:Lij0/a;


# direct methods
.method public constructor <init>(Lcr0/k;Lv80/b;Lq80/l;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lw80/h;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v2, v1}, Lw80/h;-><init>(Ljava/util/List;I)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lw80/i;->h:Lcr0/k;

    .line 12
    .line 13
    iput-object p2, p0, Lw80/i;->i:Lv80/b;

    .line 14
    .line 15
    iput-object p3, p0, Lw80/i;->j:Lq80/l;

    .line 16
    .line 17
    iput-object p4, p0, Lw80/i;->k:Lij0/a;

    .line 18
    .line 19
    new-instance p1, Lvo0/e;

    .line 20
    .line 21
    const/16 p2, 0x9

    .line 22
    .line 23
    invoke-direct {p1, p0, v2, p2}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 27
    .line 28
    .line 29
    return-void
.end method
