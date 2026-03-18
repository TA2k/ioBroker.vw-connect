.class public final Lfr0/h;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lcr0/l;

.field public final i:Lij0/a;

.field public final j:Lkf0/k;

.field public final k:Ltr0/b;


# direct methods
.method public constructor <init>(Lcr0/l;Lij0/a;Lkf0/k;Ltr0/b;)V
    .locals 2

    .line 1
    new-instance v0, Lfr0/g;

    .line 2
    .line 3
    const/16 v1, 0x3f

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lfr0/g;-><init>(I)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lfr0/h;->h:Lcr0/l;

    .line 12
    .line 13
    iput-object p2, p0, Lfr0/h;->i:Lij0/a;

    .line 14
    .line 15
    iput-object p3, p0, Lfr0/h;->j:Lkf0/k;

    .line 16
    .line 17
    iput-object p4, p0, Lfr0/h;->k:Ltr0/b;

    .line 18
    .line 19
    new-instance p1, Ldm0/h;

    .line 20
    .line 21
    const/4 p2, 0x0

    .line 22
    const/16 p3, 0x13

    .line 23
    .line 24
    invoke-direct {p1, p0, p2, p3}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method
