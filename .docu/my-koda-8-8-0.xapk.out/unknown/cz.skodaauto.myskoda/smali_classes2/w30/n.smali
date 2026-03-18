.class public final Lw30/n;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lij0/a;

.field public final i:Lu30/c;

.field public final j:Lu30/h0;

.field public final k:Lrq0/d;


# direct methods
.method public constructor <init>(Lij0/a;Lu30/c;Lu30/h0;Lrq0/d;)V
    .locals 6

    .line 1
    new-instance v0, Lw30/m;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const-string v1, ""

    .line 5
    .line 6
    const/4 v2, 0x0

    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    invoke-direct/range {v0 .. v5}, Lw30/m;-><init>(Ljava/lang/String;Lql0/g;ZZZ)V

    .line 10
    .line 11
    .line 12
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 13
    .line 14
    .line 15
    iput-object p1, p0, Lw30/n;->h:Lij0/a;

    .line 16
    .line 17
    iput-object p2, p0, Lw30/n;->i:Lu30/c;

    .line 18
    .line 19
    iput-object p3, p0, Lw30/n;->j:Lu30/h0;

    .line 20
    .line 21
    iput-object p4, p0, Lw30/n;->k:Lrq0/d;

    .line 22
    .line 23
    new-instance p1, Lw30/l;

    .line 24
    .line 25
    const/4 p2, 0x0

    .line 26
    const/4 p3, 0x0

    .line 27
    invoke-direct {p1, p0, p2, p3}, Lw30/l;-><init>(Lw30/n;Lkotlin/coroutines/Continuation;I)V

    .line 28
    .line 29
    .line 30
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 31
    .line 32
    .line 33
    return-void
.end method
