.class public final Lw30/t0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lu30/g;

.field public final i:Lij0/a;

.field public final j:Ltr0/b;

.field public final k:Lbh0/i;


# direct methods
.method public constructor <init>(Lu30/g;Lij0/a;Ltr0/b;Lbh0/i;)V
    .locals 4

    .line 1
    new-instance v0, Lw30/s0;

    .line 2
    .line 3
    const-string v1, ""

    .line 4
    .line 5
    const/4 v2, 0x0

    .line 6
    const/4 v3, 0x0

    .line 7
    invoke-direct {v0, v1, v1, v3, v2}, Lw30/s0;-><init>(Ljava/lang/String;Ljava/lang/String;Lql0/g;Z)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p1, p0, Lw30/t0;->h:Lu30/g;

    .line 14
    .line 15
    iput-object p2, p0, Lw30/t0;->i:Lij0/a;

    .line 16
    .line 17
    iput-object p3, p0, Lw30/t0;->j:Ltr0/b;

    .line 18
    .line 19
    iput-object p4, p0, Lw30/t0;->k:Lbh0/i;

    .line 20
    .line 21
    new-instance p1, Lvo0/e;

    .line 22
    .line 23
    const/4 p2, 0x6

    .line 24
    invoke-direct {p1, p0, v3, p2}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 25
    .line 26
    .line 27
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 28
    .line 29
    .line 30
    return-void
.end method
