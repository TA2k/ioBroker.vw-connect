.class public final Lw30/x;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lu30/e;

.field public final i:Lu30/i0;

.field public final j:Lij0/a;

.field public final k:Lrq0/d;


# direct methods
.method public constructor <init>(Lu30/e;Lu30/i0;Lij0/a;Lrq0/d;)V
    .locals 7

    .line 1
    new-instance v0, Lw30/w;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/4 v6, 0x0

    .line 5
    const-string v1, ""

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    move-object v2, v1

    .line 10
    invoke-direct/range {v0 .. v6}, Lw30/w;-><init>(Ljava/lang/String;Ljava/lang/String;Lql0/g;ZZZ)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lw30/x;->h:Lu30/e;

    .line 17
    .line 18
    iput-object p2, p0, Lw30/x;->i:Lu30/i0;

    .line 19
    .line 20
    iput-object p3, p0, Lw30/x;->j:Lij0/a;

    .line 21
    .line 22
    iput-object p4, p0, Lw30/x;->k:Lrq0/d;

    .line 23
    .line 24
    new-instance p1, Lw30/v;

    .line 25
    .line 26
    const/4 p2, 0x0

    .line 27
    const/4 p3, 0x0

    .line 28
    invoke-direct {p1, p0, p2, p3}, Lw30/v;-><init>(Lw30/x;Lkotlin/coroutines/Continuation;I)V

    .line 29
    .line 30
    .line 31
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 32
    .line 33
    .line 34
    return-void
.end method
