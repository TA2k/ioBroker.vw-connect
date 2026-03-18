.class public final Lw30/x0;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lu30/h;

.field public final i:Lu30/k0;

.field public final j:Lwr0/i;

.field public final k:Lij0/a;

.field public final l:Lrq0/d;


# direct methods
.method public constructor <init>(Lu30/h;Lu30/k0;Lwr0/i;Lij0/a;Lrq0/d;)V
    .locals 7

    .line 1
    new-instance v0, Lw30/w0;

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
    invoke-direct/range {v0 .. v6}, Lw30/w0;-><init>(Ljava/lang/String;Ljava/lang/String;Lql0/g;ZZZ)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lw30/x0;->h:Lu30/h;

    .line 17
    .line 18
    iput-object p2, p0, Lw30/x0;->i:Lu30/k0;

    .line 19
    .line 20
    iput-object p3, p0, Lw30/x0;->j:Lwr0/i;

    .line 21
    .line 22
    iput-object p4, p0, Lw30/x0;->k:Lij0/a;

    .line 23
    .line 24
    iput-object p5, p0, Lw30/x0;->l:Lrq0/d;

    .line 25
    .line 26
    new-instance p1, Lw30/v0;

    .line 27
    .line 28
    const/4 p2, 0x0

    .line 29
    const/4 p3, 0x0

    .line 30
    invoke-direct {p1, p0, p3, p2}, Lw30/v0;-><init>(Lw30/x0;Lkotlin/coroutines/Continuation;I)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 34
    .line 35
    .line 36
    new-instance p1, Lw30/v0;

    .line 37
    .line 38
    const/4 p2, 0x1

    .line 39
    invoke-direct {p1, p0, p3, p2}, Lw30/v0;-><init>(Lw30/x0;Lkotlin/coroutines/Continuation;I)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 43
    .line 44
    .line 45
    return-void
.end method
