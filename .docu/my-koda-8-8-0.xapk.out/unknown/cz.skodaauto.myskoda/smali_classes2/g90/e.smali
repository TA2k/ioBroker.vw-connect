.class public final Lg90/e;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lcs0/x;

.field public final i:Lcs0/h0;

.field public final j:Lij0/a;


# direct methods
.method public constructor <init>(Lcs0/x;Lcs0/h0;Lij0/a;)V
    .locals 3

    .line 1
    new-instance v0, Lg90/d;

    .line 2
    .line 3
    const/4 v1, 0x7

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v2, v1}, Lg90/d;-><init>(Ljava/util/List;I)V

    .line 6
    .line 7
    .line 8
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 9
    .line 10
    .line 11
    iput-object p1, p0, Lg90/e;->h:Lcs0/x;

    .line 12
    .line 13
    iput-object p2, p0, Lg90/e;->i:Lcs0/h0;

    .line 14
    .line 15
    iput-object p3, p0, Lg90/e;->j:Lij0/a;

    .line 16
    .line 17
    new-instance p1, Ldm0/h;

    .line 18
    .line 19
    const/16 p2, 0x18

    .line 20
    .line 21
    invoke-direct {p1, p0, v2, p2}, Ldm0/h;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method
